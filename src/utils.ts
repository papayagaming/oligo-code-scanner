import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as cache from '@actions/tool-cache'
import * as github from '@actions/github'
import * as fs from 'fs'

import stream from 'stream'
const GRYPE_VERSION = 'v0.79.1'
const grypeBinary = 'grype'
const grypeVersion = GRYPE_VERSION
export interface IVulnerability {
  id: string
  severity: string
  dataSource: string
  links: string[]
  description: string
  fixedInVersion?: string
  cvss?: {
    source: string
    type: string
    version: string
    vector: string
    metrics?: {
      baseScore: number
      exploitabilityScore: number
      impactScore: number
    }
    vendorMetadata: { [id: string]: string }
  }[]
  fix?: {
    versions: string[]
    state: string
  }
}
export interface IGrypeFinding {
  vulnerability: IVulnerability
  artifact: IArtifact
  relatedVulnerabilities: IVulnerability[]
}
export interface IArtifact {
  id?: string
  name: string
  version: string
  type: string
  foundBy: string[]
  locations: {
    path: string
    layerID?: string
  }[]
}
export function getResultsDiff(
  head: IGrypeFinding[],
  base: IGrypeFinding[]
): IGrypeFinding[] {
  const results: IGrypeFinding[] = []
  for (const headItem of head) {
    const baseItem = base.find(
      (item: IGrypeFinding) =>
        item.artifact.name === headItem.artifact.name &&
        item.artifact.version === headItem.artifact.version &&
        item.vulnerability.id === headItem.vulnerability.id
    )
    if (!baseItem) {
      results.push(headItem)
    }
  }
  return results
}

interface GroupedVulnerability {
  packageName: string
  packageVersion: string
  parentPackage?: {
    name: string
    version: string
    location: string
  }
  cves: string[]
  severity: string[]
  ecosystem: string
  location: string
  sources: string[]
  cvssScores: string[]
  descriptions: string[]
  fixVersions: string[]
  bestFixVersion?: string
}

function findBestFixVersion(versions: string[]): string | undefined {
  if (!versions.length) return undefined

  // Remove duplicates
  const uniqueVersions = Array.from(new Set(versions))

  // Sort versions in descending order (assuming semantic versioning)
  return uniqueVersions.sort((a, b) => {
    const aParts = a.split('.').map(p => parseInt(p.replace(/[^0-9]/g, ''), 10))
    const bParts = b.split('.').map(p => parseInt(p.replace(/[^0-9]/g, ''), 10))

    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      const aVal = aParts[i] || 0
      const bVal = bParts[i] || 0
      if (aVal !== bVal) return bVal - aVal
    }
    return 0
  })[0]
}

function groupVulnerabilities(
  findings: IGrypeFinding[]
): GroupedVulnerability[] {
  const groupedMap = new Map<string, GroupedVulnerability>()

  findings.forEach(finding => {
    const key = finding.artifact.name
    const location = finding.artifact.locations[0]?.path || 'unknown'

    // Find the root dependency declaration based on ecosystem
    let parentPackage:
      | { name: string; version: string; location: string }
      | undefined

    try {
      switch (finding.artifact.type.toLowerCase()) {
        case 'npm':
          parentPackage = findNpmParent(key, location)
          break
        case 'python':
          parentPackage = findPythonParent(key, location)
          break
        case 'maven':
          parentPackage = findMavenParent(key, location)
          break
        case 'gradle':
          parentPackage = findGradleParent(key, location)
          break
        case 'cargo':
          parentPackage = findCargoParent(key, location)
          break
        case 'gem':
          parentPackage = findGemParent(key, location)
          break
        case 'go':
          parentPackage = findGoParent(key, location)
          break
        default:
          parentPackage = findGenericParent(key, location)
      }
    } catch (error) {
      core.debug(`Error finding parent package: ${error}`)
    }

    if (!groupedMap.has(key)) {
      groupedMap.set(key, {
        packageName: finding.artifact.name,
        packageVersion: finding.artifact.version,
        parentPackage,
        cves: [],
        severity: [],
        ecosystem: finding.artifact.type,
        location: parentPackage?.location || location,
        sources: [],
        cvssScores: [],
        descriptions: [],
        fixVersions: []
      })
    }

    const group = groupedMap.get(key)!
    if (!group.cves.includes(finding.vulnerability.id)) {
      group.cves.push(finding.vulnerability.id)
      group.severity.push(finding.vulnerability.severity)
      group.sources.push(finding.vulnerability.dataSource)
      group.descriptions.push(finding.vulnerability.description)

      const cvssScore = finding.vulnerability.cvss
        ?.map(cvss => cvss.metrics?.baseScore.toString())
        .filter(score => score)
        .join(',')
      if (cvssScore) {
        group.cvssScores.push(cvssScore)
      }

      if (finding.vulnerability.fix?.versions.length) {
        group.fixVersions.push(...finding.vulnerability.fix.versions)
      }
    }
  })

  // Calculate best fix version for each group
  for (const group of groupedMap.values()) {
    group.bestFixVersion = findBestFixVersion(group.fixVersions)
  }

  return Array.from(groupedMap.values())
}

// Helper functions for finding parent packages in different ecosystems
function findNpmParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'npm')
}

function findPythonParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'python')
}

function findMavenParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'maven')
}

function findGradleParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'gradle')
}

function findCargoParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'cargo')
}

function findGemParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'gem')
}

function findGoParent(packageName: string, location: string) {
  return findParentPackage(packageName, location, 'go')
}

function findGenericParent(packageName: string, location: string) {
  // Try each package manager in turn
  for (const type of Object.keys(packageManagers)) {
    const result = findParentPackage(packageName, location, type)
    if (result) return result
  }
  return undefined
}

export function mapToReport(
  results: IGrypeFinding[],
  headers: string
): { markdown: string; json: { [key: string]: string | undefined }[] } {
  const groupedResults = groupVulnerabilities(results)

  // Generate both formats
  const markdown = generateVulnerabilityReport(groupedResults)
  const json = generateJsonReport(groupedResults, headers)

  return { markdown, json }
}

async function downloadGrype(version = grypeVersion): Promise<string> {
  const url = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`

  core.info(`Installing ${version}`)

  // TODO: when grype starts supporting unreleased versions, support it here
  // Download the installer, and run
  const installPath = await cache.downloadTool(url)
  // Make sure the tool's executable bit is set
  await exec.exec(`chmod +x ${installPath}`)

  const cmd = `${installPath} -b ${installPath}_grype ${version}`
  await exec.exec(cmd)
  const grypePath = `${installPath}_grype/grype`

  // Cache the downloaded file
  return cache.cacheFile(grypePath, `grype`, `grype`, version)
}

async function installGrype(version = grypeVersion): Promise<string> {
  let grypePath = cache.find(grypeBinary, version)
  if (!grypePath) {
    // Not found, install it
    grypePath = await downloadGrype(version)
  }

  // Add tool to path for this and future actions to use
  core.addPath(grypePath)
  return `${grypePath}/${grypeBinary}`
}

// Determines if multiple arguments are defined
export function multipleDefined(...args: string[]): boolean {
  let defined = false
  for (const a of args) {
    if (defined && a) {
      return true
    }
    if (a) {
      defined = true
    }
  }
  return false
}

export function sourceInput(): { head: string; base?: string } {
  // var image = core.getInput("image");
  let path = core.getInput('path')
  const basePath = core.getInput('base-path')
  // var sbom = core.getInput("sbom");

  // if (multipleDefined(image, path, sbom)) {
  //   throw new Error(
  //     "The following options are mutually exclusive: image, path, sbom"
  //   );
  // }

  // if (image) {
  //   return image;
  // }

  // if (sbom) {
  //   return "sbom:" + sbom;
  // }

  if (!path) {
    // Default to the CWD
    path = '.'
  }
  if (basePath) {
    return { head: `dir:${path}`, base: `dir:${basePath}` }
  }
  return { head: `dir:${path}` }
}

/**
 * Wait for a number of milliseconds. Resolves with 'done!' after the wait time.
 */
export async function runScan({
  source,
  failBuild,
  severityCutoff,
  onlyFixed,
  outputFormat,
  addCpesIfNone,
  byCve,
  vex
}: {
  source: string
  failBuild: string
  severityCutoff: string
  onlyFixed: string
  outputFormat: string
  addCpesIfNone: string
  byCve: string
  vex?: string
}): Promise<{
  sarif?: string
  json?: IGrypeFinding[]
}> {
  const out: {
    sarif?: string
    json?: IGrypeFinding[]
  } = {}

  const env = {
    ...process.env,
    GRYPE_CHECK_FOR_APP_UPDATE: 'true'
  }

  const SEVERITY_LIST = ['negligible', 'low', 'medium', 'high', 'critical']
  const FORMAT_LIST = ['sarif', 'json', 'table']
  const cmdArgs: string[] = []

  if (core.isDebug()) {
    cmdArgs.push(`-vv`)
  }

  const parsedOnlyFixed = onlyFixed.toLowerCase() === 'true'
  const parsedAddCpesIfNone = addCpesIfNone.toLowerCase() === 'true'
  const parsedByCve = byCve.toLowerCase() === 'true'

  cmdArgs.push('-o', outputFormat)

  if (
    !SEVERITY_LIST.some(
      item =>
        typeof severityCutoff.toLowerCase() === 'string' &&
        item === severityCutoff.toLowerCase()
    )
  ) {
    throw new Error(
      `Invalid severity-cutoff value is set to ${severityCutoff} - please ensure you are choosing either negligible, low, medium, high, or critical`
    )
  }
  if (
    !FORMAT_LIST.some(
      item =>
        typeof outputFormat.toLowerCase() === 'string' &&
        item === outputFormat.toLowerCase()
    )
  ) {
    throw new Error(
      `Invalid output-format value is set to ${outputFormat} - please ensure you are choosing either json or sarif`
    )
  }
  core.info(`Installing grype version ${grypeVersion}`)
  await installGrype(grypeVersion)

  core.info(`Source: ${source}`)
  core.info(`Fail Build: ${failBuild}`)
  core.info(`Severity Cutoff: ${severityCutoff}`)
  core.info(`Only Fixed: ${onlyFixed}`)
  core.info(`Add Missing CPEs: ${addCpesIfNone}`)
  core.info(`Orient by CVE: ${byCve}`)
  core.info(`Output Format: ${outputFormat}`)

  core.info('Creating options for GRYPE analyzer')

  // Run the grype analyzer
  let cmdOutput = ''
  const cmd = `${grypeBinary}`
  if (severityCutoff !== '') {
    cmdArgs.push('--fail-on')
    cmdArgs.push(severityCutoff.toLowerCase())
  }
  if (parsedOnlyFixed === true) {
    cmdArgs.push('--only-fixed')
  }
  if (parsedAddCpesIfNone === true) {
    cmdArgs.push('--add-cpes-if-none')
  }
  if (parsedByCve === true) {
    cmdArgs.push('--by-cve')
  }
  if (vex) {
    cmdArgs.push('--vex')
    cmdArgs.push(vex)
  }
  cmdArgs.push(source)

  // This /dev/null writable stream is required so the entire Grype output
  // is not written to the GitHub action log. the listener below
  // will actually capture the output
  const outStream = new stream.Writable({
    write(buffer, encoding, next) {
      next()
    }
  })

  const exitCode = await core.group(`${cmd} output...`, async () => {
    core.info(`Executing: ${cmd} ${cmdArgs.join(' ')}`)

    return exec.exec(cmd, cmdArgs, {
      env,
      ignoreReturnCode: true,
      outStream,
      listeners: {
        stdout(buffer: { toString: () => string }) {
          cmdOutput += buffer.toString()
        },
        stderr(buffer: { toString: () => string }) {
          core.info(buffer.toString())
        },
        debug(message: string) {
          core.info(message)
        }
      }
    })
  })

  if (core.isDebug()) {
    core.debug('Grype output:')
    core.debug(cmdOutput)
  }

  switch (outputFormat) {
    case 'sarif': {
      // const SARIF_FILE = "./results.sarif";
      // fs.writeFileSync(SARIF_FILE, cmdOutput);
      out.sarif = cmdOutput
      break
    }
    case 'json': {
      // const REPORT_FILE = "./results.json";
      // fs.writeFileSync(REPORT_FILE, );
      try {
        core.debug(`Parsing command output: ${cmdOutput}`)
        const parsed = JSON.parse(cmdOutput)
        core.debug(`Parsed JSON structure: ${JSON.stringify(parsed)}`)
        out.json = parsed.matches
        core.info(`Extracted matches: ${out.json?.length ?? 'undefined'} items`)
      } catch (error) {
        core.info(`Error parsing JSON output: ${error}`)
        out.json = []
      }
      break
    }
    default: // e.g. table
      core.info(cmdOutput)
  }

  // If there is a non-zero exit status code there are a couple of potential reporting paths
  if (exitCode > 0) {
    if (!severityCutoff) {
      // There was a non-zero exit status but it wasn't because of failing severity, this must be
      // a grype problem
      core.warning('grype had a non-zero exit status when running')
    }
    // There is a non-zero exit status code with severity cut off, although there is still a chance this is grype
    // that is broken, it will most probably be a failed severity. Using warning here will make it bubble up in the
    // Actions UI
    else
      core.warning(
        `Failed minimum severity level. Found vulnerabilities with level '${severityCutoff}' or higher`
      )
  }

  return out
}

function generateVersionDiff(
  currentVersion: string,
  fixVersion: string,
  location: string,
  parentPackage?: { name: string; version: string; location: string }
): string {
  // If we have a parent package, use its location instead
  const targetLocation = parentPackage?.location || location
  const path = targetLocation.toLowerCase()
  let diffFormat: string

  if (parentPackage) {
    // Generate diff for the parent package's dependency
    diffFormat = [
      `[**${targetLocation}**](${getRelativeFileLink(targetLocation)})`,
      '```diff',
      `-    "${parentPackage.name}": "${currentVersion}"`,
      `+    "${parentPackage.name}": "${fixVersion}"`,
      '```',
      '',
      '> ℹ️ This package is a dependency of ' + parentPackage.name
    ].join('\n')
  } else {
    // Use existing diff generation logic for direct dependencies
    if (path.includes('package-lock.json')) {
      const packageJsonPath = location.replace(
        'package-lock.json',
        'package.json'
      )
      diffFormat = generateNpmDiff(currentVersion, fixVersion, packageJsonPath)
    } else if (path.includes('yarn.lock')) {
      const packageJsonPath = location.replace('yarn.lock', 'package.json')
      diffFormat = generateNpmDiff(currentVersion, fixVersion, packageJsonPath)
    } else if (path.endsWith('package.json')) {
      diffFormat = generateNpmDiff(currentVersion, fixVersion, location)
    } else if (path.endsWith('requirements.txt')) {
      diffFormat = generatePipDiff(currentVersion, fixVersion, location)
    } else if (path.endsWith('pom.xml')) {
      diffFormat = generateMavenDiff(currentVersion, fixVersion, location)
    } else if (
      path.endsWith('build.gradle') ||
      path.endsWith('build.gradle.kts')
    ) {
      diffFormat = generateGradleDiff(currentVersion, fixVersion, location)
    } else if (path.endsWith('cargo.toml')) {
      diffFormat = generateCargoDiff(currentVersion, fixVersion, location)
    } else if (path.endsWith('go.mod')) {
      diffFormat = generateGoDiff(currentVersion, fixVersion, location)
    } else {
      diffFormat = generateGenericDiff(currentVersion, fixVersion, location)
    }
  }

  return diffFormat
}

function generateNpmDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-    "version": "${currentVersion}"`,
    `+    "version": "${fixVersion}"`,
    '```'
  ].join('\n')
}

function generatePipDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  const packageName = location.split('/').pop()?.split('==')[0] || 'package'
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-${packageName}==${currentVersion}`,
    `+${packageName}==${fixVersion}`,
    '```'
  ].join('\n')
}

function generateMavenDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-        <version>${currentVersion}</version>`,
    `+        <version>${fixVersion}</version>`,
    '```'
  ].join('\n')
}

function generateGradleDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-    implementation "group:name:${currentVersion}"`,
    `+    implementation "group:name:${fixVersion}"`,
    '```'
  ].join('\n')
}

function generateCargoDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-version = "${currentVersion}"`,
    `+version = "${fixVersion}"`,
    '```'
  ].join('\n')
}

function generateBundlerDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-gem 'package', '${currentVersion}'`,
    `+gem 'package', '${fixVersion}'`,
    '```'
  ].join('\n')
}

function generateGoDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-require package v${currentVersion}`,
    `+require package v${fixVersion}`,
    '```'
  ].join('\n')
}

function generateGenericDiff(
  currentVersion: string,
  fixVersion: string,
  location: string
): string {
  return [
    `[**${location}**](${getRelativeFileLink(location)})`,
    '```diff',
    `-version: ${currentVersion}`,
    `+version: ${fixVersion}`,
    '```'
  ].join('\n')
}

function generateVulnerabilityReport(
  groupedResults: GroupedVulnerability[]
): string {
  const packageGroups = new Map<string, GroupedVulnerability[]>()

  // Group by package name
  groupedResults.forEach(vuln => {
    const key = vuln.packageName
    if (!packageGroups.has(key)) {
      packageGroups.set(key, [])
    }
    packageGroups.get(key)?.push(vuln)
  })

  const sections: string[] = []

  // Generate markdown for each package
  for (const [packageName, vulns] of packageGroups) {
    const firstVuln = vulns[0]
    const currentVersion = firstVuln.packageVersion
    const bestFix = firstVuln.bestFixVersion

    // Get highest severity
    const severityMap: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      negligible: 1
    } as const

    const severityColors: Record<string, string> = {
      critical: 'cc0000',
      high: 'ff4d4d',
      medium: 'ff9900',
      low: '99cc00',
      negligible: '999999'
    } as const

    const highestSeverity = Array.from(
      new Set(vulns.flatMap(v => v.severity))
    ).sort((a, b) => {
      const aSeverity = severityMap[a.toLowerCase()] || 0
      const bSeverity = severityMap[b.toLowerCase()] || 0
      return bSeverity - aSeverity
    })[0]

    const severityColor =
      severityColors[highestSeverity.toLowerCase()] || '999999'

    const section = [
      `### 📦 ${packageName}@${currentVersion}`,
      '',
      `![${highestSeverity}](https://img.shields.io/badge/severity-${highestSeverity}-${severityColor})`,
      '',
      '#### 🔍 Vulnerabilities',
      ''
    ]

    // Group vulnerabilities by severity
    const vulnsBySeverity = new Map<string, GroupedVulnerability[]>()
    vulns.forEach(v => {
      const sev = v.severity[0]
      if (!vulnsBySeverity.has(sev)) {
        vulnsBySeverity.set(sev, [])
      }
      vulnsBySeverity.get(sev)?.push(v)
    })

    // Add vulnerabilities grouped by severity
    for (const [severity, sevVulns] of vulnsBySeverity) {
      section.push(`<details>`)
      section.push(
        `<summary><strong>${severity}</strong> Vulnerabilities</summary>`
      )
      section.push('')

      sevVulns.forEach(vuln => {
        const cveLinks = vuln.cves
          .map(cve => `[\`${cve}\`](https://nvd.nist.gov/vuln/detail/${cve})`)
          .join(' ')

        section.push(`- **CVE**: ${cveLinks}`)
        if (vuln.cvssScores.length) {
          section.push(`  - **CVSS**: ${vuln.cvssScores.join(', ')}`)
        }
        if (vuln.descriptions.length) {
          section.push(`  - **Description**: ${vuln.descriptions[0]}`)
        }
        section.push('')
      })

      section.push('</details>')
      section.push('')
    }

    // Add fix information
    if (bestFix) {
      section.push('#### 🛠️ Recommended Fix')
      section.push('')
      section.push(`Upgrade to version \`${bestFix}\``)
      section.push('')
      section.push('<details>')
      section.push('<summary>📝 View upgrade diff</summary>')
      section.push('')
      section.push(
        generateVersionDiff(
          currentVersion,
          bestFix,
          firstVuln.location,
          firstVuln.parentPackage
        )
      )
      section.push('</details>')
    } else {
      section.push('#### ⚠️ No Fix Available')
      section.push('')
      section.push(
        '> Consider reviewing this dependency for alternatives or implementing additional security controls.'
      )
    }

    section.push('\n---\n')
    sections.push(section.join('\n'))
  }

  return `# 🔒 Security Vulnerability Report

<details>
<summary><strong> Vulnerability Details</strong></summary>

${sections.join('\n')}

> 💡 This report shows newly introduced vulnerabilities. Each package includes its severity, CVE details, and recommended fixes.
> 
> - 🔍 Click on CVE links to view detailed vulnerability information
> - 📝 Expand sections to view more details
> - 🛠️ Follow the recommended fixes to resolve vulnerabilities

</details>`
}

function generateJsonReport(
  groupedResults: GroupedVulnerability[],
  headers: string
): { [key: string]: string | undefined }[] {
  const headerFields = headers.split(',')
  const jsonReport = groupedResults.map(vuln => {
    const reportEntry: { [key: string]: string | undefined } = {}

    headerFields.forEach(header => {
      switch (header.trim()) {
        case 'CVE':
          reportEntry[header] = vuln.cves.join(', ')
          break
        case 'Package Name':
          reportEntry[header] = vuln.packageName
          break
        case 'Package Version':
          reportEntry[header] = vuln.packageVersion
          break
        case 'Ecosystem':
          reportEntry[header] = vuln.ecosystem
          break
        case 'Location':
          reportEntry[header] = vuln.location
          break
        case 'Source':
          reportEntry[header] = vuln.sources.join(', ')
          break
        case 'Severity':
          reportEntry[header] = Array.from(new Set(vuln.severity)).join(', ')
          break
        case 'CVSS':
          reportEntry[header] = Array.from(new Set(vuln.cvssScores)).join(', ')
          break
        case 'Description':
          reportEntry[header] = Array.from(new Set(vuln.descriptions)).join(
            '\n'
          )
          break
        case 'Fix Versions':
          reportEntry[header] = Array.from(new Set(vuln.fixVersions)).join(', ')
          break
        case 'Best Fix':
          reportEntry[header] = vuln.bestFixVersion || 'No fix available'
          break
        default:
          reportEntry[header] = undefined
      }
    })

    return reportEntry
  })

  return jsonReport
}

function getRelativeFileLink(location: string): string {
  // Get the repository information from GitHub context
  const context = github.context
  const { owner, repo } = context.repo
  const prNumber = context.payload.pull_request?.number

  if (!prNumber) return location

  // Create a link to the file in the PR
  return `https://github.com/${owner}/${repo}/blob/${context.sha}/${location}`
}

interface DependencyInfo {
  name: string
  version: string
  dependencies?: { [key: string]: string }
  devDependencies?: { [key: string]: string }
}

interface PackageManagerHelper {
  getRootPackageFile: (location: string) => string
  parsePackageFile: (content: string) => DependencyInfo
  findDependencyInTree: (
    packageName: string,
    tree: DependencyInfo
  ) =>
    | {
        name: string
        version: string
        location: string
      }
    | undefined
}

const packageManagers: Record<string, PackageManagerHelper> = {
  npm: {
    getRootPackageFile: (location: string) => {
      const parts = location.split('node_modules/')
      return `${parts[0]}package.json`
    },
    parsePackageFile: (content: string) => JSON.parse(content),
    findDependencyInTree: (packageName: string, tree: DependencyInfo) => {
      const version =
        tree.dependencies?.[packageName] || tree.devDependencies?.[packageName]
      if (version) {
        return {
          name: packageName,
          version: version,
          location: 'package.json'
        }
      }
      return undefined
    }
  },
  python: {
    getRootPackageFile: (location: string) => {
      const rootDir =
        location.split('site-packages/')[0] ||
        location.split('dist-packages/')[0]
      const possibleFiles = ['requirements.txt', 'setup.py', 'pyproject.toml']
      for (const file of possibleFiles) {
        const fullPath = `${rootDir}/${file}`
        if (fs.existsSync(fullPath)) return fullPath
      }
      return `${rootDir}/requirements.txt`
    },
    parsePackageFile: (content: string) => {
      const deps: { [key: string]: string } = {}
      content.split('\n').forEach(line => {
        const match = line.match(
          /^([^=><\s]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([^#\s]+)?/
        )
        if (match) {
          deps[match[1]] = match[3] || '*'
        }
      })
      return { name: '', version: '', dependencies: deps }
    },
    findDependencyInTree: (packageName: string, tree: DependencyInfo) => {
      if (tree.dependencies?.[packageName]) {
        return {
          name: packageName,
          version: tree.dependencies[packageName],
          location: 'requirements.txt'
        }
      }
      return undefined
    }
  },
  maven: {
    getRootPackageFile: (location: string) => {
      const rootDir = location.split('repository/')[0]
      return `${rootDir}/pom.xml`
    },
    parsePackageFile: (content: string) => {
      // Simple XML parsing - in practice you'd want to use a proper XML parser
      const deps: { [key: string]: string } = {}
      const matches = content.matchAll(
        /<dependency>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>[\s\S]*?<\/dependency>/g
      )
      for (const match of matches) {
        deps[match[1]] = match[2]
      }
      return { name: '', version: '', dependencies: deps }
    },
    findDependencyInTree: (packageName: string, tree: DependencyInfo) => {
      if (tree.dependencies?.[packageName]) {
        return {
          name: packageName,
          version: tree.dependencies[packageName],
          location: 'pom.xml'
        }
      }
      return undefined
    }
  }
}

function findParentPackage(
  packageName: string,
  location: string,
  type: string
): { name: string; version: string; location: string } | undefined {
  const helper = packageManagers[type.toLowerCase()]
  if (!helper) return undefined

  try {
    const rootPackageFile = helper.getRootPackageFile(location)
    const content = fs.readFileSync(rootPackageFile, 'utf8')
    const packageInfo = helper.parsePackageFile(content)
    return helper.findDependencyInTree(packageName, packageInfo)
  } catch (error) {
    core.debug(`Error finding parent package: ${error}`)
    return undefined
  }
}
