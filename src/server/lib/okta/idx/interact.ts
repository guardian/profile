import { Request } from 'express';
import { ResponseWithRequestState } from '@/server/models/Express';
import { logger } from '@/server/lib/serverSideLogger';
import { AuthorizationParameters, generators } from 'openid-client';
import { getConfiguration } from '@/server/lib/getConfiguration';
import {
	AuthorizationState,
	ProfileOpenIdClientRedirectUris,
	generateAuthorizationState,
	setAuthorizationStateCookie,
} from '@/server/lib/okta/openid-connect';
import {
	PerformAuthorizationCodeFlowOptions,
	scopesForAuthentication,
} from '@/server/lib/okta/oauth';
import { joinUrl } from '@guardian/libs';
import { z } from 'zod';
import { closeCurrentSession } from '@/server/lib/okta/api/sessions';
import { getPersistableQueryParams } from '@/shared/lib/queryParams';
import { OAuthError, isOAuthError } from '@/server/models/okta/Error';
import { trackMetric } from '@/server/lib/trackMetric';

const { okta } = getConfiguration();

const interactResponseSchema = z.object({
	interaction_handle: z.string(),
});
export type InteractResponse = z.infer<typeof interactResponseSchema>;

/**
 * @name interact
 * @description Okta IDX API/Interaction Code flow - Step 1: Initiates the interaction code flow, and returns an interaction handle which should be used in the next step, specifically `introspect`
 *
 * This is very similar to the standard authorization code flow, using similar parameters and the PKCE flow, but the authentication
 * is different.
 *
 * In Gateway we only use the interaction code flow for authentication, in order to avoid using the Okta hosted sign in page. The
 * standard authorization code flow is used for everything else.
 *
 * @param req - Express request
 * @param res - Express response
 * @param AuthorizationCodeFlowOptions - Subset of the `PerformAuthorizationCodeFlowOptions` used by our standard authorization code flow, namely the parameters needed for authentication
 * @returns Promise<[InteractResponse, AuthorizationState]> - Array containing the interaction handle and the authorization state
 */
export const interact = async (
	req: Request,
	res: ResponseWithRequestState,
	{
		confirmationPagePath,
		closeExistingSession,
		doNotSetLastAccessCookie = false,
		extraData,
		login_hint,
	}: Pick<
		PerformAuthorizationCodeFlowOptions,
		| 'confirmationPagePath'
		| 'closeExistingSession'
		| 'doNotSetLastAccessCookie'
		| 'extraData'
		| 'login_hint'
	>,
): Promise<[InteractResponse, AuthorizationState]> => {
	try {
		// determines if the current session, should it exist, be closed
		if (closeExistingSession) {
			// Okta Identity Engine session cookie is called `idx`
			const oktaIdentityEngineSessionCookieId: string | undefined =
				req.cookies.idx;
			if (oktaIdentityEngineSessionCookieId) {
				await closeCurrentSession({
					idx: oktaIdentityEngineSessionCookieId,
					ip: req.ip,
				});
			}
		}

		// generate the code verifier and code challenge for PKCE
		// see https://www.oauth.com/oauth2-servers/pkce/authorization-request/
		// the `code_verifier` is a cryptographically random string
		// the `code_challenge` is the `code_verifier` hashed with SHA-256 and then base64url encoded
		const codeVerifier = generators.codeVerifier(64);
		const codeChallenge = generators.codeChallenge(codeVerifier);

		// generate and store a "state"
		// as a http only, secure, signed session cookie
		// which is a json object that contains a stateParam and the query params
		// the stateParam is used to protect against csrf
		// we also set additional data in the state cookie that we need to persist
		// between the authorization request and the callback
		const authState = generateAuthorizationState(
			getPersistableQueryParams(res.locals.queryParams),
			confirmationPagePath,
			doNotSetLastAccessCookie,
			{
				appPrefix: extraData?.appPrefix,
				encryptedRegistrationConsents: extraData?.encryptedRegistrationConsents,
				codeVerifier,
			},
		);
		setAuthorizationStateCookie(authState, res);

		// set up the authorization parameters to send to the /interact endpoint
		// in order to start the interaction code flow
		// see https://developer.okta.com/docs/concepts/interaction-code/
		const authorizationParams: AuthorizationParameters = {
			// the client_id is the id of the client application
			client_id: okta.clientId,
			// only use the interaction code flow callback uri, everything else is handled by standard authorization code flow
			redirect_uri: ProfileOpenIdClientRedirectUris.INTERACTION_CODE,
			// only authentication scopes for interaction code flow, everything else is handled by standard authorization code flow
			scope: scopesForAuthentication.join(' '),
			// we send the generated code challenge
			code_challenge: codeChallenge,
			// we use the S256 code challenge method, which is the only method supported
			code_challenge_method: 'S256',
			// we send the generated stateParam as the state parameter
			state: authState.stateParam,
			// todo: test login_hint
			login_hint,
		};

		const authorizationSearchParams = new URLSearchParams(
			authorizationParams as Record<string, string>,
		);

		const response = await fetch(
			joinUrl(okta.orgUrl, '/oauth2/', okta.authServerId, '/v1/interact'),
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
				},
				body: authorizationSearchParams.toString(),
			},
		);

		if (!response.ok) {
			// Check if the body is likely json using the content-type header
			const contentType = response.headers.get('content-type');
			if (contentType?.includes('application/json')) {
				// if so, parse the body as json, and handle the error
				const error = await response.json().catch((e) => {
					throw new OAuthError(
						{
							error: 'invalid_json',
							error_description: e.message,
						},
						response.status,
					);
				});

				if (isOAuthError(error)) {
					throw new OAuthError(error, response.status);
				}
			} else {
				throw new OAuthError(
					{
						error: 'unknown_error',
						error_description: await response.text(),
					},
					response.status,
				);
			}
		}

		const interactResponse = interactResponseSchema.parse(
			await response.json(),
		);

		trackMetric('OktaIDXInteract::Success');

		return [interactResponse, authState];
	} catch (error) {
		trackMetric('OktaIDXInteract::Failure');
		logger.error('Error - Okta IDX interact:', error);

		throw error;
	}
};
