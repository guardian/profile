// Middleware for assigning important parts of the request state to res.requestState.
// This should be the only place res.requestState is mutated.
// Requires: csurf middlware
import { getGeolocationRegion } from '@/server/lib/getGeolocationRegion';
import { parseExpressQueryParams } from '@/server/lib/queryParams';
import { NextFunction, Response } from 'express';
import { getConfiguration } from '@/server/lib/getConfiguration';
import { tests } from '@/shared/model/experiments/abTests';
import { getABTesting } from '@/server/lib/getABTesting';
import { RequestState, RequestWithTypedQuery } from '@/server/models/Express';
import Bowser from 'bowser';
import { logger } from '@/server/lib/serverSideLogger';
import { getApp } from '@/server/lib/okta/api/apps';
import { IsNativeApp } from '@/shared/model/ClientState';

const {
  idapiBaseUrl,
  oauthBaseUrl,
  googleRecaptcha,
  stage,
  githubRunNumber,
  sentryDsn,
} = getConfiguration();

const getRequestState = async (
  req: RequestWithTypedQuery,
): Promise<RequestState> => {
  const [abTesting, abTestAPI] = getABTesting(req, tests);

  // tracking parameters might be from body too
  const { ref, refViewId } = req.body;

  const queryParams = parseExpressQueryParams(
    req.method,
    {
      ...req.query,
      // returnUrl may be a query parameter or referrer header
      returnUrl: req.query.returnUrl || req.get('Referrer'),
    },
    {
      ref,
      refViewId,
    },
  );

  const browser = Bowser.getParser(req.header('user-agent') || 'unknown');

  // we also need to know if the flow was initiated by a native app, hence we get the app info from the api
  // and determine this based on the label, whether it contains "android" or "ios"
  let isNativeApp: IsNativeApp;

  try {
    if (!!queryParams.appClientId) {
      const app = await getApp(queryParams.appClientId);

      const label = app.label.toLowerCase();

      if (label.startsWith('android_')) {
        isNativeApp = 'android';
      } else if (label.startsWith('ios_')) {
        isNativeApp = 'ios';
      }
    }
  } catch (error) {
    logger.error('Error getting app info in request state', error, {
      request_id: req.get('x-request-id'),
    });
  }

  return {
    queryParams,
    pageData: {
      geolocation: getGeolocationRegion(req),
      returnUrl: queryParams.returnUrl,
      isNativeApp,
    },
    globalMessage: {},
    csrf: {
      token: req.csrfToken(),
    },
    abTesting: abTesting,
    abTestAPI: abTestAPI,
    clientHosts: {
      idapiBaseUrl,
      oauthBaseUrl,
    },
    recaptchaConfig: { recaptchaSiteKey: googleRecaptcha.siteKey },
    ophanConfig: {
      bwid: req.cookies.bwid,
      consentUUID: req.cookies.consentUUID,
      viewId: queryParams.refViewId,
    },
    sentryConfig: {
      build: githubRunNumber,
      stage,
      dsn: sentryDsn,
    },
    browser: browser.getBrowser(),
    requestId: req.get('x-request-id'),
  };
};

export const requestStateMiddleware = async (
  req: RequestWithTypedQuery,
  res: Response,
  next: NextFunction,
) => {
  try {
    const state = await getRequestState(req);

    /* This is the only place mutation of res.requestState should occur */
    /* eslint-disable-next-line functional/immutable-data */
    res.requestState = state;

    return next();
  } catch (error) {
    logger.error('Error in requestStateMiddleware', error);
    return next(error);
  }
};
