import { Request } from 'express';
import { authenticate as authenticateWithOkta } from '@/server/lib/okta/api/authentication';
import { logger } from '@/server/lib/serverSideLogger';
import { renderer } from '@/server/lib/renderer';
import { ResponseWithRequestState } from '@/server/models/Express';
import { trackMetric } from '@/server/lib/trackMetric';
import { handleAsyncErrors } from '@/server/lib/expressWrappers';
import { getConfiguration } from '@/server/lib/getConfiguration';
import { decrypt } from '@/server/lib/idapi/decryptToken';
import {
	FederationErrors,
	GenericErrors,
	PasscodeErrors,
	RegistrationErrors,
	SignInErrors,
} from '@/shared/model/Errors';
import { ApiError } from '@/server/models/Error';
import { rateLimitedTypedRouter as router } from '@/server/lib/typedRoutes';
import { readEmailCookie } from '@/server/lib/emailCookie';
import handleRecaptcha from '@/server/lib/recaptcha';
import { OAuthError, OktaError } from '@/server/models/okta/Error';
import {
	performAuthorizationCodeFlow,
	scopesForAuthentication,
} from '@/server/lib/okta/oauth';
import { getCurrentSession } from '@/server/lib/okta/api/sessions';
import { redirectIfLoggedIn } from '@/server/lib/middleware/redirectIfLoggedIn';
import { getUser, getUserGroups } from '@/server/lib/okta/api/users';
import { clearOktaCookies } from '@/server/routes/signOut';
import { sendOphanComponentEventFromQueryParamsServer } from '@/server/lib/ophan';
import { isBreachedPassword } from '@/server/lib/breachedPasswordCheck';
import { mergeRequestState } from '@/server/lib/requestState';
import { addQueryParamsToPath } from '@/shared/lib/queryParams';
import {
	readEncryptedStateCookie,
	setEncryptedStateCookie,
} from '@/server/lib/encryptedStateCookie';
import { sendEmailToUnvalidatedUser } from '@/server/lib/unvalidatedEmail';
import {
	ProfileOpenIdClientRedirectUris,
	setAuthorizationStateCookie,
	updateAuthorizationStateData,
} from '@/server/lib/okta/openid-connect';
import { SocialProvider, isValidSocialProvider } from '@/shared/model/Social';
import { interact } from '@/server/lib/okta/idx/interact';
import {
	introspect,
	redirectIdpSchema,
} from '@/server/lib/okta/idx/introspect';
import {
	oktaIdxApiSignInController,
	oktaIdxApiSignInPasscodeController,
	oktaIdxApiSubmitPasscodeController,
	oktaSignInControllerErrorHandler,
} from '@/server/controllers/signInControllers';
import { convertExpiresAtToExpiryTimeInMs } from '@/server/lib/okta/idx/shared/convertExpiresAtToExpiryTimeInMs';
import OktaJwtVerifier from '@okta/jwt-verifier';

const { okta, accountManagementUrl, defaultReturnUri, passcodesEnabled } =
	getConfiguration();

/**
 * Helper method to determine if a global error should show on the sign in page
 * and return a user facing error if so
 * if there's no error it returns undefined
 * @param error - error query parameter
 * @param error_description - error_description query parameter
 * @returns string | undefined - user facing error message
 */
export const getErrorMessageFromQueryParams = (
	error?: string,
	error_description?: string,
) => {
	// show error if account linking required
	if (error === FederationErrors.SOCIAL_SIGNIN_BLOCKED) {
		return SignInErrors.SOCIAL_SIGNIN_ERROR;
	}
	// Show error if provisioning failed
	if (error === RegistrationErrors.PROVISIONING_FAILURE) {
		return error;
	}

	if (error === PasscodeErrors.PASSCODE_EXPIRED) {
		return PasscodeErrors.PASSCODE_EXPIRED;
	}

	// We propagate a generic error message when we don't know what the exact error is
	// This error will also include a request id, so users can contact us with this information
	if (error_description) {
		return SignInErrors.GENERIC;
	}
};

/**
 * Controller to render the sign in page in both IDAPI and Okta
 */
router.get(
	'/signin',
	redirectIfLoggedIn,
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		const state = res.locals;
		const { encryptedEmail, error, error_description, signInEmail } =
			state.queryParams;

		// first attempt to get email from IDAPI encryptedEmail if it exists
		const decryptedEmail =
			encryptedEmail && (await decrypt(encryptedEmail, req.ip));

		// followed by the gateway EncryptedState
		// if it exists
		const email = decryptedEmail || signInEmail || readEmailCookie(req);

		const html = renderer('/signin', {
			requestState: mergeRequestState(state, {
				pageData: {
					email,
					focusPasswordField: !!email,
				},
				globalMessage: {
					error: getErrorMessageFromQueryParams(error, error_description),
				},
			}),
			pageTitle: 'Sign in',
		});
		return res.type('html').send(html);
	}),
);

router.get(
	'/signin/email-sent',
	(req: Request, res: ResponseWithRequestState) => {
		const state = res.locals;
		const html = renderer('/signin/email-sent', {
			requestState: mergeRequestState(state, {
				pageData: {
					email: readEncryptedStateCookie(req)?.email,
				},
			}),
			pageTitle: 'Check Your Inbox',
		});
		res.type('html').send(html);
	},
);

router.post(
	'/signin/email-sent/resend',
	handleRecaptcha,
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		const {
			queryParams: { appClientId },
		} = res.locals;

		try {
			const encryptedState = readEncryptedStateCookie(req);
			const { email } = encryptedState ?? {};

			if (typeof email == 'undefined') {
				throw new OktaError({
					message:
						'Could not resend unvalidated user email as email was undefined',
				});
			}

			const user = await getUser(email, req.ip);
			const { id } = user;
			const groups = await getUserGroups(id, req.ip);
			// check if the user has their email validated based on group membership
			const emailValidated = groups.some(
				(group) => group.profile.name === 'GuardianUser-EmailValidated',
			);
			if (emailValidated) {
				throw new OktaError({
					message:
						'Could not resend unvalidated user email as user is already validated.',
				});
			}

			await sendEmailToUnvalidatedUser({
				id,
				email: user.profile.email,
				appClientId,
				ip: req.ip,
			});
			setEncryptedStateCookie(res, {
				email: user.profile.email,
			});

			return res.redirect(
				303,
				addQueryParamsToPath('/signin/email-sent', res.locals.queryParams, {
					emailSentSuccess: true,
				}),
			);
		} catch (error) {
			logger.error('Okta unvalidated user resend email failure', error);
			return res.type('html').send(
				renderer('/signin/email-sent', {
					pageTitle: 'Check Your Inbox',
					requestState: mergeRequestState(res.locals, {
						pageData: {
							formError: GenericErrors.DEFAULT,
						},
					}),
				}),
			);
		}
	}),
);

// We don't do any session checking on /reauthenticate - if someone's ended up
// here, it's probably because their session is invalid or expired and they need
// to be allowed to attempt to sign in again.
router.get(
	'/reauthenticate',
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		const state = res.locals;
		const { encryptedEmail, error, error_description } = state.queryParams;

		// first attempt to get email from IDAPI encryptedEmail if it exists
		const decryptedEmail =
			encryptedEmail && (await decrypt(encryptedEmail, req.ip));

		// followed by the gateway EncryptedState
		// if it exists
		const email = decryptedEmail || readEmailCookie(req);

		const html = renderer('/reauthenticate', {
			requestState: mergeRequestState(state, {
				pageData: {
					email,
					focusPasswordField: !!email,
				},
				globalMessage: {
					error: getErrorMessageFromQueryParams(error, error_description),
				},
			}),
			pageTitle: 'Sign in',
		});
		res.type('html').send(html);
	}),
);

router.post(
	'/reauthenticate',
	handleRecaptcha,
	handleAsyncErrors((req: Request, res: ResponseWithRequestState) => {
		const {
			queryParams: { appClientId },
		} = res.locals;
		// if okta feature switch enabled, use okta authentication
		return oktaSignInController({
			req,
			res,
			isReauthenticate: true,
			appClientId,
		});
	}),
);

router.post(
	'/signin',
	handleRecaptcha,
	redirectIfLoggedIn,
	handleAsyncErrors((req: Request, res: ResponseWithRequestState) => {
		const {
			queryParams: { appClientId },
		} = res.locals;
		// if okta feature switch enabled, use okta authentication
		return oktaSignInController({
			req,
			res,
			isReauthenticate: false,
			appClientId,
		});
	}),
);

// Essentially the email-sent page, but for passcode sign in
// we're not using /signin/email-sent as that route is used by the security/email validation flow
router.get(
	'/signin/code',
	redirectIfLoggedIn,
	(req: Request, res: ResponseWithRequestState) => {
		const state = res.locals;

		const encryptedState = readEncryptedStateCookie(req);

		if (encryptedState?.email && encryptedState.stateHandle) {
			try {
				const html = renderer('/signin/code', {
					requestState: mergeRequestState(state, {
						pageData: {
							email: readEncryptedStateCookie(req)?.email,
							timeUntilTokenExpiry: convertExpiresAtToExpiryTimeInMs(
								encryptedState.stateHandleExpiresAt,
							),
						},
					}),
					pageTitle: 'Check Your Inbox',
				});
				return res.type('html').send(html);
			} catch (error) {
				logger.error(`${req.method} ${req.originalUrl} Error`, error);
			}
		}

		// on error, redirect to the sign in page
		return res.redirect(
			303,
			addQueryParamsToPath('/signin', state.queryParams),
		);
	},
);

router.post(
	'/signin/code',
	redirectIfLoggedIn,
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		return await oktaIdxApiSubmitPasscodeController({ req, res });
	}),
);

router.get(
	'/signin/code/expired',
	(_: Request, res: ResponseWithRequestState) => {
		return res.redirect(
			303,
			addQueryParamsToPath('/signin', res.locals.queryParams, {
				error: PasscodeErrors.PASSCODE_EXPIRED,
			}),
		);
	},
);

// route to resend the email for passcode sign in
// Essentially the same as POST /signin, but call the correct controller
router.post(
	'/signin/code/resend',
	redirectIfLoggedIn,
	handleRecaptcha,
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		await oktaIdxApiSignInPasscodeController({ req, res });
	}),
);

const oktaSignInController = async ({
	req,
	res,
	isReauthenticate = false,
	appClientId,
}: {
	req: Request;
	res: ResponseWithRequestState;
	isReauthenticate?: boolean;
	appClientId?: string;
}) => {
	// get the email and password from the request body
	const { email = '', password = '' } = req.body;

	// Okta Identity Engine session cookie is called `idx`
	const oktaIdentityEngineSessionCookieId: string | undefined = req.cookies.idx;

	if (!isReauthenticate) {
		try {
			if (oktaIdentityEngineSessionCookieId) {
				// if a session already exists then we redirect back to the returnUrl for apps, and the dotcom homepage for web
				await getCurrentSession({
					idx: oktaIdentityEngineSessionCookieId,
					ip: req.ip,
				});
				return res.redirect(accountManagementUrl);
			}
		} catch {
			// We log this scenario as it is quite unlikely, but we continue to sign the user in.
			logger.info(
				'User POSTed to /signin with an invalid `idx` session cookie',
				undefined,
			);
		}
	}

	try {
		// idx api flow
		if (passcodesEnabled && !res.locals.queryParams.useOktaClassic) {
			// try to start the IDX flow to sign in the user with a password
			await oktaIdxApiSignInController({
				req,
				res,
			});
			// if successful, the user will be redirected
			// so we need to check if the headers have been sent to prevent further processing
			if (res.headersSent) {
				return;
			}
		}

		// attempt to authenticate with okta
		// if authentication fails, it will fall through to the catch
		// the response contains a one time use sessionToken that we can exchange
		// for a session cookie
		const response = await authenticateWithOkta(
			{
				username: email,
				password,
			},
			req.ip,
		);

		// we only support the SUCCESS status for Okta authentication in gateway
		// Other statuses could be supported in the future https://developer.okta.com/docs/reference/api/authn/#transaction-state
		if (response.status !== 'SUCCESS') {
			throw new ApiError({
				message:
					'User authenticating was blocked due to unsupported Okta Authentication status property',
				status: 403,
			});
		}

		// fire ophan component event if applicable when a session is set
		if (res.locals.queryParams.componentEventParams) {
			void sendOphanComponentEventFromQueryParamsServer(
				res.locals.queryParams.componentEventParams,
				'SIGN_IN',
				'web',
				res.locals.ophanConfig.consentUUID,
			);
		}

		// we're authenticated track this metric
		trackMetric('OktaSignIn::Success');

		if (response._embedded?.user.id) {
			// retrieve the user groups
			const groups = await getUserGroups(response._embedded.user.id, req.ip);

			// check if the user has their email validated based on group membership
			const emailValidated = groups.some(
				(group) => group.profile.name === 'GuardianUser-EmailValidated',
			);

			// check the user password strength
			const hasWeakPassword = await isBreachedPassword(password);

			// For MVP2 we want to log if the user is in one of the 4 following states
			// 1. User is in the GuardianUser-EmailValidated group and has a strong password
			// 2. User is in the GuardianUser-EmailValidated group and has a weak password
			// 3. User is not in the GuardianUser-EmailValidated group and has a strong password
			// 4. User is not in the GuardianUser-EmailValidated group and has a weak password
			if (emailValidated && !hasWeakPassword) {
				trackMetric('User-EmailValidated-StrongPassword');
			} else if (emailValidated && hasWeakPassword) {
				trackMetric('User-EmailValidated-WeakPassword');
			} else if (!emailValidated && !hasWeakPassword) {
				trackMetric('User-EmailNotValidated-StrongPassword');
			} else if (!emailValidated && hasWeakPassword) {
				trackMetric('User-EmailNotValidated-WeakPassword');
			}

			if (!emailValidated) {
				await sendEmailToUnvalidatedUser({
					id: response._embedded.user.id,
					email: response._embedded.user.profile.login,
					appClientId,
					ip: req.ip,
				});
				setEncryptedStateCookie(res, {
					email: response._embedded.user.profile.login,
				});

				return res.redirect(
					303,
					addQueryParamsToPath('/signin/email-sent', res.locals.queryParams, {
						emailSentSuccess: true,
					}),
				);
			}
		}

		// we now need to generate an okta session
		// so we'll call the OIDC /authorize endpoint which sets a session cookie
		// we'll pretty much be performing the Authorization Code Flow
		return await performAuthorizationCodeFlow(req, res, {
			sessionToken: response.sessionToken,
			closeExistingSession: true,
			prompt: 'none',
			scopes: scopesForAuthentication,
			redirectUri: ProfileOpenIdClientRedirectUris.AUTHENTICATION,
		});
	} catch (error) {
		trackMetric('OktaSignIn::Failure');

		logger.error('Okta authentication error:', error);

		const { status, gatewayError } = oktaSignInControllerErrorHandler(error);

		const html = renderer('/signin', {
			requestState: mergeRequestState(res.locals, {
				pageData: {
					email,
					formError: gatewayError,
				},
			}),
			pageTitle: 'Sign in',
		});

		return res.status(status).type('html').send(html);
	}
};

/**
 * If an Okta session exists, this route will re-authenticate the Okta session
 * and also refresh the IDAPI session concurrently, synchronising the expiry
 * times of the Okta and IDAPI sessions, before returning the client to the URL
 * they came from.
 */
router.get(
	'/signin/refresh',
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		const { returnUrl } = res.locals.queryParams;
		// Okta Identity Engine session cookie is called `idx`
		const oktaIdentityEngineSessionCookieId: string | undefined =
			req.cookies.idx;

		const redirectUrl = returnUrl || defaultReturnUri;

		// Check if the user has an existing Okta session.
		if (oktaIdentityEngineSessionCookieId) {
			try {
				// If the user session is valid, we re-authenticate them, supplying
				// the idx cookie value to Okta.
				await getCurrentSession({
					idx: oktaIdentityEngineSessionCookieId,
					ip: req.ip,
				});
				return performAuthorizationCodeFlow(req, res, {
					doNotSetLastAccessCookie: true,
					prompt: 'none',
					scopes: scopesForAuthentication,
					redirectUri: ProfileOpenIdClientRedirectUris.AUTHENTICATION,
				});
			} catch {
				//if the cookie exists, but the session is invalid, we remove the cookie
				//and return them to the URL they came from
				clearOktaCookies(res);
				return res.redirect(redirectUrl);
			}
		} else {
			// If there are no Okta cookies, why are you here? We bail and
			// send the client to the /signin page.
			return res.redirect('/signin');
		}
	}),
);

router.get(
	'/signin/password',
	(req: Request, res: ResponseWithRequestState) => {
		const state = res.locals;
		const email =
			state.queryParams.signInEmail || readEncryptedStateCookie(req)?.email;
		const html = renderer('/signin/password', {
			requestState: mergeRequestState(state, {
				pageData: {
					email,
					focusPasswordField: !!email,
				},
			}),
			pageTitle: 'Sign in',
		});
		return res.type('html').send(html);
	},
);

const googleJwtVerifier = new OktaJwtVerifier({
	issuer: 'https://accounts.google.com',
	clientId:
		'774465807556-pkevncqpfs9486ms0bo5q1f2g9vhpior.apps.googleusercontent.com',
	jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
});

router.get(
	'/signin/:social',
	handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
		const socialIdp = req.params.social as SocialProvider;

		if (!isValidSocialProvider(socialIdp)) {
			return res.redirect(303, '/signin');
		}

		// get the IDP id from the config
		const idp = okta.social[socialIdp];

		// fire ophan component event if applicable when a session is set
		if (res.locals.queryParams.componentEventParams) {
			void sendOphanComponentEventFromQueryParamsServer(
				res.locals.queryParams.componentEventParams,
				'SIGN_IN',
				req.params.social,
				res.locals.ophanConfig.consentUUID,
			);
		}

		console.log('got', res.locals.queryParams.got);
		console.log('socialIdp', idp);
		if (socialIdp === 'google' && res.locals.queryParams.got) {
			try {
				const token = await googleJwtVerifier.verifyIdToken(
					res.locals.queryParams.got,
					'774465807556-pkevncqpfs9486ms0bo5q1f2g9vhpior.apps.googleusercontent.com',
				);
				console.log('token', token);
				const email = token.claims.email as string;

				return await performAuthorizationCodeFlow(req, res, {
					idp,
					closeExistingSession: true,
					scopes: scopesForAuthentication,
					redirectUri: ProfileOpenIdClientRedirectUris.AUTHENTICATION,
					login_hint: email,
					extraData: {
						socialProvider: socialIdp,
					},
				});
			} catch (error) {
				console.log('error', error);
			}
			return res.status(200).json({
				got: res.locals.queryParams.got,
			});
		}

		// OKTA IDX API FLOW
		// attempt to authenticate social using the idx api/interaction code flow
		// if this fails with any error, we fall back to okta hosted flow
		try {
			const [{ interaction_handle }, authState] = await interact(req, res, {
				closeExistingSession: true,
			});

			const introspectResponse = await introspect(
				{
					interactionHandle: interaction_handle,
				},
				req.ip,
			);

			const updatedAuthState = updateAuthorizationStateData(authState, {
				socialProvider: socialIdp,
				stateToken: introspectResponse.stateHandle.split('~')[0],
			});

			setAuthorizationStateCookie(updatedAuthState, res);

			const introspectIdp = introspectResponse.remediation.value.find(
				({ name, type }) =>
					name === 'redirect-idp' && type === socialIdp.toUpperCase(),
			);

			if (introspectIdp && redirectIdpSchema.safeParse(introspectIdp).success) {
				const redirectIdp = redirectIdpSchema.parse(introspectIdp);

				trackMetric('OktaIDXSocialSignIn::Redirect');

				return res.redirect(303, redirectIdp.href);
			} else {
				throw new OAuthError(
					{
						error: 'invalid_response',
						error_description: 'Invalid or missing redirect-idp remediation',
					},
					404,
				);
			}
		} catch (error) {
			trackMetric('OktaIDXSocialSignIn::Failure');
			logger.error('IDX API - Social sign in error:', error);
		}

		// OKTA LEGACY SOCIAL FLOW
		// if okta feature switch enabled, perform authorization code flow with idp
		return await performAuthorizationCodeFlow(req, res, {
			idp,
			closeExistingSession: true,
			scopes: scopesForAuthentication,
			redirectUri: ProfileOpenIdClientRedirectUris.AUTHENTICATION,
			extraData: {
				socialProvider: socialIdp,
			},
		});
	}),
);

export default router.router;
