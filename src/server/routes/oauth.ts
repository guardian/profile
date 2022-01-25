import { typedRouter as router } from '@/server/lib/typedRoutes';
import { Request } from 'express';
import { ResponseWithRequestState } from '@/server/models/Express';
import {
  deleteAuthorizationStateCookie,
  getAuthorizationStateCookie,
  OpenIdErrors,
  ProfileOpenIdClient,
  ProfileOpenIdClientRedirectUris,
} from '@/server/lib/okta/openid-connect';
import { getConfiguration } from '@/server/lib/getConfiguration';
import { logger } from '@/server/lib/serverSideLogger';
import { trackMetric } from '@/server/lib/trackMetric';
import { handleAsyncErrors } from '@/server/lib/expressWrappers';
import { exchangeAccessTokenForCookies } from '@/server/lib/idapi/auth';
import { setIDAPICookies } from '@/server/lib/setIDAPICookies';
import { SignInErrors } from '@/shared/model/Errors';
import {
  readEncryptedStateCookie,
  setEncryptedStateCookie,
} from '@/server/lib/encryptedStateCookie';
import { addQueryParamsToPath } from '@/shared/lib/queryParams';

interface OAuthError {
  error: string;
  error_description: string;
}

const { defaultReturnUri } = getConfiguration();

/**
 * Type guard to check that a given error is an OAuth error.
 * By checking for the `error` and `error_description` properties
 * @param {unknown} obj
 * @return {boolean}
 */
const isOAuthError = (
  maybeOAuthError: unknown,
): maybeOAuthError is OAuthError => {
  const { error, error_description } = maybeOAuthError as OAuthError;
  return error !== undefined && error_description !== undefined;
};

/**
 * Helper method to redirect back to the sign in page with
 * a generic error message if we don't want to expose the error
 * back to the client. Be sure to log the error though!
 */
const redirectForGenericError = (
  req: Request,
  res: ResponseWithRequestState,
) => {
  // we set the sign in redirect to true so that we can render the sign in page
  // without getting into a redirect loop
  const encryptedState = readEncryptedStateCookie(req);
  setEncryptedStateCookie(res, {
    ...encryptedState,
    signInRedirect: true,
  });

  return res.redirect(
    addQueryParamsToPath('/signin', res.locals.queryParams, {
      error_description: SignInErrors.GENERIC,
    }),
  );
};

router.get(
  '/oauth/authorization-code/callback',
  handleAsyncErrors(async (req: Request, res: ResponseWithRequestState) => {
    try {
      // params returned from the /authorize endpoint
      // for auth code flow they will be "code" and "state"
      // "code" is the authorization code to exchange for access token
      // "state" will be the "nonce" value set in the oidc_auth_state cookie
      // if there were any errors, then an "error", and "error_description" params
      // will be returned instead
      const callbackParams = ProfileOpenIdClient.callbackParams(req);

      // get the oidc_auth_state cookie which contains the "nonce"
      // and "returnUrl" so we can get the user back to the page they
      // initially landed on sign in from
      const authState = getAuthorizationStateCookie(req);

      // check if the state cookie exists, this should be set at the start of the OAuth flow
      // e.g. at sign in
      if (!authState) {
        // If this doesn't exist, that would mean that either
        // a) the state isn't being set correctly, or
        // b) someone is trying to attack the oauth flow
        // for example with an invalid state cookie, or without the state cookie
        // the state cookie is used to prevent CSRF attacks
        logger.error('Missing auth state cookie on OAuth Callback!');
        trackMetric('OAuthAuthorization::Failure');
        return redirectForGenericError(req, res);
      }

      // we have the Authorization State now, so the cookie is
      // no longer required, so mark cookie for deletion in the response
      deleteAuthorizationStateCookie(res);

      // check if the callback params contain an login_required error
      // used to check if a session existed before the user is shown a sign in page
      if (
        isOAuthError(callbackParams) &&
        callbackParams.error === OpenIdErrors.LOGIN_REQUIRED
      ) {
        // set the signInRedirect flag so we can render the sign in page as a session doesn't exist
        const encryptedState = readEncryptedStateCookie(req);
        setEncryptedStateCookie(res, {
          ...encryptedState,
          signInRedirect: true,
        });

        return res.redirect(
          addQueryParamsToPath('/signin', authState.queryParams),
        );
      }

      // exchange the auth code for access token + id token
      // and check the "state" we got back from the callback
      // to the "nonce" that was set in the AuthorizationState
      // to prevent CSRF attacks
      const tokenSet = await ProfileOpenIdClient.callback(
        // the redirectUri is the callback location (this route)
        ProfileOpenIdClientRedirectUris.WEB,
        // the params sent to the callback
        callbackParams,
        // checks to make sure that everything is valid
        {
          // we're doing the auth code flow, so check for the correct type
          response_type: 'code',
          // check that the nonce is the same
          state: authState.nonce,
        },
      );

      // this is just to handle potential errors where we don't get back an access token
      if (!tokenSet.access_token) {
        logger.error(
          'Missing access_token from /token endpoint in OAuth Callback',
        );
        trackMetric('OAuthAuthorization::Failure');
        return redirectForGenericError(req, res);
      }

      // call the IDAPI /auth/oauth-token endpoint
      // to exchange the access token for identity cookies
      // the idapi introspects the access token and if valid
      // will generate and sign cookies for the user the
      // token belonged to
      const cookies = await exchangeAccessTokenForCookies(
        tokenSet.access_token,
        req.ip,
      );

      // adds set cookie headers
      setIDAPICookies(res, cookies);

      // track the success metric
      trackMetric('OAuthAuthorization::Success');

      // return to url from state or default url
      return res.redirect(
        303,
        authState.queryParams.returnUrl || defaultReturnUri,
      );
    } catch (error) {
      // check if it's an oauth/oidc error
      if (isOAuthError(error)) {
        // log the specific error
        logger.error('OAuth/OIDC Error:', error);
      }

      // log and track the error
      logger.error(`${req.method} ${req.originalUrl}  Error`, error);
      trackMetric('OAuthAuthorization::Failure');

      // fallthrough redirect to sign in with generic error
      return redirectForGenericError(req, res);
    }
  }),
);

export default router.router;
