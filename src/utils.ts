import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as cache from '@actions/tool-cache'
import * as github from '@actions/github'

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

    if (!groupedMap.has(key)) {
      groupedMap.set(key, {
        packageName: finding.artifact.name,
        packageVersion: finding.artifact.version,
        cves: [],
        severity: [],
        ecosystem: finding.artifact.type,
        location,
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
  location: string
): string {
  // Detect package management system based on file path
  const path = location.toLowerCase()
  let diffFormat: string

  if (path.endsWith('package.json')) {
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
  } else if (path.endsWith('gemfile')) {
    diffFormat = generateBundlerDiff(currentVersion, fixVersion, location)
  } else if (path.endsWith('go.mod')) {
    diffFormat = generateGoDiff(currentVersion, fixVersion, location)
  } else {
    // Default to generic version format
    diffFormat = generateGenericDiff(currentVersion, fixVersion, location)
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
      section.push(
        `<details ${
          severity.toLowerCase() === highestSeverity.toLowerCase() ? 'open' : ''
        }>`
      )
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
        generateVersionDiff(currentVersion, bestFix, firstVuln.location)
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

${sections.join('\n')}

> 💡 This report shows newly introduced vulnerabilities. Each package includes its severity, CVE details, and recommended fixes.
> 
> - 🔍 Click on CVE links to view detailed vulnerability information
> - 📝 Expand sections to view more details
> - 🛠️ Follow the recommended fixes to resolve vulnerabilities`
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
