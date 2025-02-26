import type { GuStackProps } from '@guardian/cdk/lib/constructs/core';
import { GuStack } from '@guardian/cdk/lib/constructs/core';
import type { App } from 'aws-cdk-lib';
import { CfnInclude } from 'aws-cdk-lib/cloudformation-include';
import { GuRole } from '@guardian/cdk/lib/constructs/iam';
import {
	Effect,
	PolicyDocument,
	PolicyStatement,
	WebIdentityPrincipal,
} from 'aws-cdk-lib/aws-iam';

export class IdentityGateway extends GuStack {
	constructor(scope: App, id: string, props: GuStackProps) {
		super(scope, id, props);

		new CfnInclude(this, 'IdentityGateway', {
			templateFile: '../cloudformation.yaml',
		});

		if (['CODE', 'TEST'].includes(props.stage)) {
			new GuRole(this, 'GithubActionsSESSendEmailsRole', {
				roleName: 'GithubActionsSESSendEmailsRole',
				assumedBy: new WebIdentityPrincipal(
					`arn:aws:iam::${this.account}:oidc-provider/token.actions.githubusercontent.com`,
					{
						StringLike: {
							'actions.githubusercontent.com:sub': 'repo:guardian/gateway:*',
						},
					},
				),
				inlinePolicies: {
					SendEmailSES: new PolicyDocument({
						statements: [
							new PolicyStatement({
								actions: ['ses:SendEmail'],
								resources: ['*'],
								effect: Effect.ALLOW,
							}),
						],
					}),
				},
			});
		}
	}
}
