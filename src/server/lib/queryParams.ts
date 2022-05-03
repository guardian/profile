import { QueryParams, TrackingQueryParams } from '@/shared/model/QueryParams';
import { validateReturnUrl, validateRefUrl } from '@/server/lib/validateUrl';
import { validateClientId } from '@/server/lib/validateClientId';

const isStringBoolean = (maybeBoolean?: string): boolean | undefined => {
  if (!maybeBoolean) {
    return undefined;
  }

  if (maybeBoolean === 'true') {
    return true;
  }

  return false;
};

const validateGetOnlyError = (
  method: string,
  error?: string,
): boolean | undefined => {
  // The error parameter causes an error message to be rendered
  // Only render this error message for GET pages
  // On POST with the error, we redirect to the GET URL of the form with the error parameter
  if (method === 'GET' && error === 'true') {
    return true;
  }
};

export const parseExpressQueryParams = (
  method: string,
  {
    returnUrl,
    clientId,
    emailVerified,
    emailSentSuccess,
    csrfError,
    recaptchaError,
    refViewId,
    ref,
    encryptedEmail,
    error,
    error_description,
    useOkta,
    componentEventParams,
    fromURI,
    appClientId,
  }: Record<keyof QueryParams, string | undefined>, // parameters from req.query
  // some parameters may be manually passed in req.body too,
  // generally for tracking purposes
  bodyParams: TrackingQueryParams = {},
): QueryParams => {
  return {
    returnUrl: validateReturnUrl(returnUrl),
    clientId: validateClientId(clientId),
    emailVerified: isStringBoolean(emailVerified),
    emailSentSuccess: isStringBoolean(emailSentSuccess),
    csrfError: validateGetOnlyError(method, csrfError),
    recaptchaError: validateGetOnlyError(method, recaptchaError),
    refViewId: refViewId || bodyParams.refViewId,
    ref: (ref || bodyParams.ref) && validateRefUrl(ref || bodyParams.ref),
    componentEventParams:
      componentEventParams || bodyParams.componentEventParams,
    encryptedEmail,
    error,
    error_description,
    useOkta: isStringBoolean(useOkta),
    fromURI,
    appClientId,
  };
};

export const addReturnUrlToPath = (path: string, returnUrl: string): string => {
  const divider = path.includes('?') ? '&' : '?';
  return `${path}${divider}returnUrl=${encodeURIComponent(returnUrl)}`;
};
