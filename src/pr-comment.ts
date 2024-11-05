import * as core from '@actions/core'
import * as github from '@actions/github'

const COMMENT_MARKER = '<!-- oligo-scanner-report -->'

export async function createOrUpdatePRComment(markdown: string): Promise<void> {
  try {
    core.info('Starting createOrUpdatePRComment')
    const token = process.env.GITHUB_TOKEN
    if (!token) {
      core.info('No GITHUB_TOKEN found in environment')
      throw new Error('GITHUB_TOKEN is required to create/update PR comments')
    }
    core.info('GITHUB_TOKEN found')

    const octokit = github.getOctokit(token)
    const context = github.context

    core.info(
      `GitHub context: ${JSON.stringify({
        eventName: context.eventName,
        payload: {
          pull_request: context.payload.pull_request ? 'exists' : 'undefined',
          issue: context.payload.issue ? 'exists' : 'undefined'
        }
      })}`
    )

    if (!context.payload.pull_request) {
      core.info('No pull request context found - skipping comment creation')
      return
    }

    const { owner, repo } = context.repo
    const issue_number = context.payload.pull_request.number

    core.info(
      `PR details: owner=${owner}, repo=${repo}, issue_number=${issue_number}`
    )

    // Search for existing comment
    core.info('Searching for existing comment')
    const comments = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number
    })

    const existingComment = comments.data.find(
      (comment: any) => comment.body?.includes(COMMENT_MARKER)
    )
    core.info(`Existing comment found: ${existingComment ? 'yes' : 'no'}`)

    const commentBody = `${COMMENT_MARKER}
## Vulnerability Scan Results

The following vulnerabilities were found in your dependencies:

${markdown}
`

    if (existingComment) {
      core.info(`Updating existing comment ID: ${existingComment.id}`)
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: commentBody
      })
      core.info('Successfully updated existing PR comment')
    } else {
      core.info('Creating new comment')
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number,
        body: commentBody
      })
      core.info('Successfully created new PR comment')
    }
  } catch (error) {
    core.info(`Error in createOrUpdatePRComment: ${error}`)
    core.warning(`Failed to create/update PR comment: ${error}`)
  }
}
