import * as core from '@actions/core'
import * as github from '@actions/github'

const COMMENT_MARKER = '<!-- oligo-scanner-report -->'

export async function createOrUpdatePRComment(markdown: string): Promise<void> {
  try {
    core.debug('Starting createOrUpdatePRComment')
    const token = process.env.GITHUB_TOKEN
    if (!token) {
      core.debug('No GITHUB_TOKEN found in environment')
      throw new Error('GITHUB_TOKEN is required to create/update PR comments')
    }
    core.debug('GITHUB_TOKEN found')

    const octokit = github.getOctokit(token)
    const context = github.context
    
    core.debug(`GitHub context: ${JSON.stringify({
      eventName: context.eventName,
      payload: {
        pull_request: context.payload.pull_request ? 'exists' : 'undefined',
        issue: context.payload.issue ? 'exists' : 'undefined'
      }
    })}`)

    if (!context.payload.pull_request) {
      core.debug('No pull request context found - skipping comment creation')
      return
    }

    const { owner, repo } = context.repo
    const issue_number = context.payload.pull_request.number
    
    core.debug(`PR details: owner=${owner}, repo=${repo}, issue_number=${issue_number}`)

    // Search for existing comment
    core.debug('Searching for existing comment')
    const comments = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number
    })

    const existingComment = comments.data.find((comment:any) => 
      comment.body?.includes(COMMENT_MARKER)
    )
    core.debug(`Existing comment found: ${existingComment ? 'yes' : 'no'}`)

    const commentBody = `${COMMENT_MARKER}\n## Vulnerability Scan Results\n\n${markdown}`

    if (existingComment) {
      core.debug(`Updating existing comment ID: ${existingComment.id}`)
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: commentBody
      })
      core.debug('Successfully updated existing PR comment')
    } else {
      core.debug('Creating new comment')
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number,
        body: commentBody
      })
      core.debug('Successfully created new PR comment')
    }
  } catch (error) {
    core.debug(`Error in createOrUpdatePRComment: ${error}`)
    core.warning(`Failed to create/update PR comment: ${error}`)
  }
}