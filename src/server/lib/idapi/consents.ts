import {
	idapiFetch,
	APIPatchOptions,
	APIGetOptions,
	APIAddOAuthAuthorization,
} from '@/server/lib/IDAPIFetch';
import { logger } from '@/server/lib/serverSideLogger';
import { ConsentsErrors } from '@/shared/model/Errors';
import { Consent } from '@/shared/model/Consent';
import { IdapiError } from '@/server/models/Error';
import {
	invertOptInConsents,
	invertOptOutConsents,
} from './invertOptOutConsents';
import { IdApiQueryParams } from '@/shared/model/IdapiQueryParams';
import { UserConsent } from '@/shared/model/UserConsents';

const handleError = (): never => {
	throw new IdapiError({ message: ConsentsErrors.GENERIC, status: 500 });
};

interface ConsentAPIResponse {
	id: string;
	isOptOut: boolean;
	isChannel: boolean;
	name: string;
	description: string;
}

const responseToEntity = (consent: ConsentAPIResponse): Consent => {
	const { name, description, id } = consent;
	return {
		id,
		description,
		name,
	};
};

const read = async ({
	filter,
	request_id,
}: {
	filter: IdApiQueryParams['filter'];
	request_id?: string;
}): Promise<Consent[]> => {
	const options = APIGetOptions();
	try {
		return (
			(await idapiFetch({
				path: '/consents',
				queryParams: {
					filter,
				},
				options,
			})) as ConsentAPIResponse[]
		).map(responseToEntity);
	} catch (error) {
		logger.error(`IDAPI Error consents read '/consents'`, error, {
			request_id,
		});
		return handleError();
	}
};

const readUserConsents = async ({
	accessToken,
	request_id,
}: {
	accessToken: string;
	request_id?: string;
}): Promise<UserConsent[]> => {
	const options = APIAddOAuthAuthorization(APIGetOptions(), accessToken);
	try {
		return (await idapiFetch({
			path: '/users/me/consents',
			options,
		})) as UserConsent[];
	} catch (error) {
		logger.error(`IDAPI Error consents read '/users/me/consents'`, error, {
			request_id,
		});
		return handleError();
	}
};

export const update = async ({
	payload,
	accessToken,
	request_id,
}: {
	payload: UserConsent[];
	accessToken: string;
	request_id?: string;
}) => {
	// Inversion required of four legitimate interest consents that are modelled as opt OUTS in the backend data model
	// but which are presented as opt INs on the client UI/UX
	const invertedPayload = invertOptInConsents(payload) as UserConsent[];
	const options = APIAddOAuthAuthorization(
		APIPatchOptions(invertedPayload),
		accessToken,
	);

	try {
		await idapiFetch({
			path: '/users/me/consents',
			options,
		});
		return;
	} catch (error) {
		logger.error(`IDAPI Error consents update  '/users/me/consents'`, error, {
			request_id,
		});
		return handleError();
	}
};

export const getUserConsentsForPage = async ({
	pageConsents,
	accessToken,
	request_id,
}: {
	pageConsents: string[];
	request_id?: string;
	accessToken: string;
}): Promise<Consent[]> => {
	// Inversion required of four legitimate interest consents that are modelled as opt OUTS in the backend data model
	// but which are presented as opt INs on the client UI/UX
	const allConsents = invertOptOutConsents(
		await read({ filter: 'all', request_id }),
	);
	const userConsents = invertOptOutConsents(
		await readUserConsents({ accessToken, request_id }),
	);

	return pageConsents
		.map((id) => allConsents.find((consent) => consent.id === id))
		.map((consent) => {
			if (consent) {
				// eslint-disable-next-line functional/no-let
				let updated = consent;
				const userConsent = userConsents.find((uc) => uc.id === consent.id);

				if (userConsent) {
					updated = {
						...updated,
						consented: userConsent.consented,
					};
				}

				return updated;
			}
		})
		.filter(Boolean) as Consent[];
};

export const getConsentValueFromRequestBody = (
	key: string,
	body: { [key: string]: string },
): boolean => {
	if (body[key] === undefined || typeof body[key] !== 'string') {
		return false;
	}

	switch (body[key]) {
		case 'true':
			return true;
		case 'false':
			return false;
		default:
			return !!body[key];
	}
};
