import * as core from '@actions/core'
import * as github from '@actions/github'

const COMMENT_MARKER = '<!-- oligo-scanner-report -->'

export async function createOrUpdatePRComment(markdown: string): Promise<void> {
  try {
    const token = process.env.GITHUB_TOKEN
    if (!token) {
      throw new Error('GITHUB_TOKEN is required to create/update PR comments')
    }

    const octokit = github.getOctokit(token)
    const context = github.context

    if (!context.payload.pull_request) {
      core.info('No pull request context found - skipping comment creation')
      return
    }

    const { owner, repo } = context.repo
    const issue_number = context.payload.pull_request.number

    // Search for existing comment
    const comments = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number
    })

    const existingComment = comments.data.find((comment:any) => 
      comment.body?.includes(COMMENT_MARKER)
    )

    const commentBody = `${COMMENT_MARKER}\n## Vulnerability Scan Results\n\n${markdown}`

    if (existingComment) {
      // Update existing comment
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: commentBody
      })
      core.debug('Updated existing PR comment')
    } else {
      // Create new comment
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number,
        body: commentBody
      })
      core.debug('Created new PR comment')
    }
  } catch (error) {
    core.warning(`Failed to create/update PR comment: ${error}`)
  }
}