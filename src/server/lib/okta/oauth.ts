import { Request } from 'express';
import { ResponseWithRequestState } from '@/server/models/Express';
import { getPersistableQueryParams } from '@/shared/lib/queryParams';
import { RoutePaths } from '@/shared/model/Routes';
import {
	generateAuthorizationState,
	setAuthorizationStateCookie,
	getOpenIdClient,
	AuthorizationState,
} from '@/server/lib/okta/openid-connect';
import { closeCurrentSession } from './api/sessions';

/**
 * List of individual scopes that can be requested by gateway
 *
 * However use one of the following lists instead of selecting individually:
 * scopesForAuthentication or scopesForApplication
 */
export type Scopes =
	| 'openid'
	| 'profile'
	| 'email'
	| 'guardian.identity-api.cookies.create.self.secure'
	| 'guardian.members-data-api.read.self'
	| 'guardian.identity-api.newsletters.read.self'
	| 'guardian.identity-api.newsletters.update.self'
	| 'guardian.identity-api.user.delete.self.secure'
	| 'id_token.profile.profile'
	| 'offline_access';

/**
 * @name scopesForAuthentication
 * @description Scopes to use when performing authentication (e.g sign in, set password)
 */
export const scopesForAuthentication: Scopes[] = [
	'openid',
	'profile',
	'email',
	'guardian.identity-api.cookies.create.self.secure',
	'guardian.members-data-api.read.self',
	'guardian.identity-api.newsletters.read.self',
	'guardian.identity-api.newsletters.update.self',
	// Required to obtain refresh tokens for the 'wait for Identity ID' loop
	'offline_access',
];

/**
 * @name scopesForApplication
 * @description Scopes to use when performing application actions (e.g. onboarding flow, post sign in prompt)
 */
export const scopesForApplication: Scopes[] = [
	'openid',
	'profile',
	'email',
	'guardian.identity-api.newsletters.read.self',
	'guardian.identity-api.newsletters.update.self',
	'guardian.members-data-api.read.self',
	'id_token.profile.profile',
];

/**
 * @name scopesForSelfServiceDeletion
 * @description Scopes to use when performing self service deletion through the /delete url
 */
export const scopesForSelfServiceDeletion: Scopes[] = [
	'openid',
	'profile',
	'email',
	'guardian.identity-api.user.delete.self.secure',
	'guardian.identity-api.newsletters.update.self',
	'guardian.members-data-api.read.self',
];

/**
 * @param closeExistingSession (optional) - if true, we'll close any existing okta session before calling the authorization code flow
 * @param confirmationPagePath (optional) - page to redirect the user to after authentication
 * @param doNotSetLastAccessCookie (optional) - if true, does not update the SC_GU_LA cookie during update of Idapi cookies.  Default false.
 * @param extraData (optional) - any extra data to store in the authorization state to persist across the auth code flow, use for small amounts of non-sensitive data and things that are not already in the query params
 * @param idp (optional) - okta id of the social identity provider to use
 * @param prompt (optional) - if provided, we'll use this to set the prompt parameter, see https://developer.okta.com/docs/reference/api/oidc/#parameter-details for prompt parameter details, N.B `undefined` has a different meaning to `none`
 * @param redirectUri - the redirect uri to use for the /authorize endpoint
 * @param scopes (optional) - any scopes to use for the /authorize endpoint, defaults to ['openid']
 * @param sessionToken (optional) - if provided, we'll use this to set the session cookie
 * @param login_hint (optional) - if provided, we'll use this to set the login_hint parameter, used for google one tap login to automatically authenticate as the user
 */
export interface PerformAuthorizationCodeFlowOptions {
	closeExistingSession?: boolean;
	confirmationPagePath?: RoutePaths;
	doNotSetLastAccessCookie?: boolean;
	extraData?: AuthorizationState['data'];
	idp?: string;
	prompt?: 'login' | 'none';
	redirectUri: string;
	scopes: Scopes[];
	sessionToken?: string | null;
	login_hint?: string;
}

/**
 * @name performAuthorizationCodeFlow
 * @description Helper method to perform the Authorization Code Flow
 *
 * Used for post authentication with the session token to set a session cookie.
 *
 * @param req - the express request object
 * @param res - the express response object
 * @param options - the options for the authorization code flow
 * @returns 303 redirect to the okta /authorize endpoint
 */
export const performAuthorizationCodeFlow = async (
	req: Request,
	res: ResponseWithRequestState,
	{
		sessionToken,
		confirmationPagePath,
		idp,
		closeExistingSession,
		doNotSetLastAccessCookie = false,
		prompt,
		scopes = ['openid'],
		redirectUri,
		login_hint,
		extraData,
	}: PerformAuthorizationCodeFlowOptions,
) => {
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

	// Determine which OpenIdClient to use, in DEV we use the DevProfileIdClient, otherwise we use the ProfileOpenIdClient
	const OpenIdClient = getOpenIdClient(req);

	// firstly we generate and store a "state"
	// as a http only, secure, signed session cookie
	// which is a json object that contains a stateParam and the query params
	// the stateParam is used to protect against csrf
	const authState = generateAuthorizationState(
		getPersistableQueryParams(res.locals.queryParams),
		confirmationPagePath,
		doNotSetLastAccessCookie,
		extraData,
	);
	setAuthorizationStateCookie(authState, res);

	// generate the /authorize endpoint url which we'll redirect the user too
	const authorizeUrl = OpenIdClient.authorizationUrl({
		// Prompt for 'login' if the idp is provided to make sure the user sees
		// the social provider login page, but only if login_hint is not provided
		// otherwise we'll use the prompt parameter provided
		prompt: idp && !login_hint ? 'login' : prompt,
		// The sessionToken from authentication to exchange for session cookie
		sessionToken,
		// we send the generated stateParam as the state parameter
		state: authState.stateParam,
		// any scopes, by default the 'openid' scope is required
		scope: scopes.join(' '),
		// the redirect_uri is the url that we'll redirect the user to after
		redirect_uri: redirectUri,
		// the identity provider if doing social login
		idp,
		// the login_hint is used for google one tap login
		login_hint,
	});

	// redirect the user to the /authorize endpoint
	return res.redirect(303, authorizeUrl);
};
