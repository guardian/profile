import { EmailType } from '@/shared/model/EmailType';
import { PersistableQueryParams } from './QueryParams';
import { RegistrationConsents } from './Consent';

export interface EncryptedState {
	email?: string;
	emailType?: EmailType;
	passwordSetOnWelcomePage?: boolean;
	status?: string;
	signInRedirect?: boolean; // TODO: possibly rename for clarity
	isCmpConsented?: boolean;
	queryParams?: PersistableQueryParams;
	registrationConsents?: RegistrationConsents;
}
