import { ValidClientId } from '@/shared/lib/clientId';

type Stringifiable = string | boolean | number | null | undefined;

export type StringifiableRecord = Record<
	string,
	Stringifiable | readonly Stringifiable[]
>;

export interface TrackingQueryParams {
	// this is the url of the referring page
	// https://github.com/guardian/ophan/blob/70b658e785c490c411670bbd3c7fde62ae0224fc/the-slab/app/extractors/ReferrerExtractor.scala#L171
	ref?: string;
	// this refViewId refers to the referral page view id
	// that the user was on to use for tracking referrals
	// https://github.com/guardian/ophan/blob/70b658e785c490c411670bbd3c7fde62ae0224fc/the-slab/app/extractors/ReferrerExtractor.scala#L129
	refViewId?: string;
	// componentEventsParams is included so that we can pass Ophan ComponentEvent information to IDAPI, allowing us to
	// fire Ophan ComponentEvent on the server with information (componentType, abTest, etc.) from the frontend client
	// the value of componentEventParams should be passed as a URL encoded string of key value pairs in the form of key=value,
	// forExample componentType=SIGN_IN_GATE&componentId=inital_test&abTestName=SignInGateFirstTest&abTestVariant=variant&viewId=k2oj70c85n0d0fbtl6tg would be url encoded as componentType%3DSIGN_IN_GATE%26componentId%3Dinital_test%26abTestName%3DSignInGateFirstTest%26abTestVariant%3Dvariant%26viewId%3Dk2oj70c85n0d0fbtl6tg
	// the valid keys for the componentEventParams componentType, componentId, abTestName, abTestVariant, viewId, browserId (optional, but in most cases you'd want this), visitId (optional, same as browserId)
	// these correspond to whats required by the Ophan ComponentEvent (https://dashboard.ophan.co.uk/docs/thrift/componentevent.html)
	// if IDAPI doesn't find the required keys in componentEventParams or fails to parse componentEventParams then the Ophan ComponentEvent will not be fired
	// we URL encode the value of componentEventParams due to the number of keys available
	// as well as getting confused with other parameters, so we thought it best to pass it as a URL encoded string, and then do the decoding once it gets to IDAPI
	componentEventParams?: string;
	listName?: string;
}

/**
 * PersistableQueryParams are query parameters
 * that are safe to persist between requests
 * for example query parameters that should be passed
 * from page to page in a flow e.g. returnUrl
 */
export interface PersistableQueryParams
	extends TrackingQueryParams,
		StringifiableRecord {
	returnUrl: string;
	clientId?: ValidClientId;
	// This is the fromURI query parameter from Otka authorization code flow
	// that we intercept in fastly. We can send a user back to this uri
	// to complete the authorization code flow for that application
	fromURI?: string;
	// This is the client Id of a calling application in Okta (ie iOS app etc)
	appClientId?: string;
	// fallback to Okta Classic if needed
	useOktaClassic?: boolean;
	// Flag to force the sign in page to use passwords, useful for testing/using previous behaviour
	usePasswordSignIn?: boolean;
}

/**
 * `QueryParams` type is made up of the `PersistableQueryParams`
 * as well as extra parameters that should not persist between
 * request or are only valid for a single request, for example an
 * `error` or state flag
 */
export interface QueryParams
	extends PersistableQueryParams,
		StringifiableRecord {
	emailVerified?: boolean;
	// used to show the success message on the email sent page
	// only if the email is resent from the email sent page
	emailSentSuccess?: boolean;
	csrfError?: boolean;
	recaptchaError?: boolean;
	encryptedEmail?: string;
	error?: string;
	error_description?: string;
	maxAge?: number;
	// only use this to prefill the email input on either sign in page, for passcode or password
	// don't rely on this for any other purpose, or to be a valid email
	signInEmail?: string;
	// google one tap jwt token
	got?: string;
}
