import * as core from '@actions/core'
import { getResultsDiff, runScan, sourceInput, mapToReport } from './utils'
import tablemark from 'tablemark'
import { createOrUpdatePRComment } from './pr-comment'

/**
 * The main function for the action.
 */
export async function run(): Promise<void> {
  try {
    core.info(new Date().toTimeString())
    // Grype accepts several input options, initially this action is supporting both `image` and `path`, so
    // a check must happen to ensure one is selected at least, and then return it
    const sourceArray = sourceInput()

    const failBuild = core.getInput('fail-build') || 'true'
    const outputFormat = core.getInput('output-format') || 'json'
    const severityCutoff = core.getInput('severity-cutoff') || 'medium'
    const onlyFixed = core.getInput('only-fixed') || 'false'
    const headers =
      core.getInput('headers') ||
      'CVE,Package Name,Package Version,Ecosystem,Location,Source,Severity,CVSS,Description,Fix Versions,Best Fix'
    const addCpesIfNone = 'true'
    const byCve = 'true'
    const vex = ''
    const createPRComment = core.getInput('create-pr-comment') === 'true'

    core.info(
      `createPRComment input value: ${core.getInput('create-pr-comment')}`
    )
    core.info(`createPRComment parsed value: ${createPRComment}`)

    const out = await runScan({
      source: sourceArray.head,
      failBuild: 'false',
      severityCutoff,
      onlyFixed,
      outputFormat,
      addCpesIfNone,
      byCve,
      vex
    })
    if (sourceArray.base) {
      const outbase = await runScan({
        source: sourceArray.base,
        failBuild: 'false',
        severityCutoff,
        onlyFixed,
        outputFormat,
        addCpesIfNone,
        byCve,
        vex
      })

      // core.setOutput("json", out.json);
      if (out.json && outbase.json) {
        const results = getResultsDiff(out.json, outbase.json)
        core.notice(`${results.length} Vulnerabilities found`)
        if (results.length > 0) {
          const report = mapToReport(results, headers)
          core.setOutput('json', report)
          const reportTable = tablemark(report)
          core.setOutput('markdown', reportTable)
          core.info(`output : ${reportTable}`)
          core.info(
            `Checking PR comment conditions: createPRComment=${createPRComment}, results.length=${results.length}`
          )
          if (createPRComment && results.length > 0) {
            core.info('Attempting to create/update PR comment for diff results')
            await createOrUpdatePRComment(reportTable)
          }
        } else {
          core.setOutput('json', [])
          core.setOutput('markdown', '')
        }
        if (failBuild === 'true' && results.length > 0) {
          core.setFailed(`${results.length} Vulnerabilities found`)
        } else {
          if (results.length === 0) {
            core.notice(`No Vulnerabilities found`)
          } else {
            core.warning(`${results.length} Vulnerabilities found`)
          }
        }
      }
    } else {
      const results = out.json
      core.info(`Scan results: ${JSON.stringify(results)}`)
      core.info(
        `Results type: ${typeof results}, is array: ${Array.isArray(results)}`
      )
      core.info(`Results length: ${results?.length}`)

      if (results) {
        core.info(`${results?.length} Vulnerabilities found`)
        if (results?.length > 0) {
          const report = mapToReport(results, headers)
          core.setOutput('json', report)
          const reportTable = tablemark(report)
          core.setOutput('markdown', reportTable)
          core.info(`output : ${reportTable}`)
          core.info(
            `Checking PR comment conditions: createPRComment=${createPRComment}, results?.length=${results?.length}`
          )
          if (createPRComment && results?.length > 0) {
            core.info(
              'Attempting to create/update PR comment for single scan results'
            )
            await createOrUpdatePRComment(reportTable)
          }
        }
      }
      if (failBuild === 'true' && results && results?.length > 0) {
        core.setFailed(`${results.length} Vulnerabilities found`)
      }
    }
  } catch (error) {
    core.setFailed(`Action failed ${error}`)
  }
}
