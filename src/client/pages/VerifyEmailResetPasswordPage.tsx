import React from 'react';
import { MainBodyText } from '@/client/components/MainBodyText';
import useClientState from '@/client/lib/hooks/useClientState';
import { ResetPassword } from '@/client/pages/ResetPassword';

export const VerifyEmailResetPasswordPage = () => {
	const clientState = useClientState();
	const {
		pageData: { email = '', formError } = {},
		queryParams,
		recaptchaConfig,
	} = clientState;
	const { recaptchaSiteKey } = recaptchaConfig;

	return (
		<ResetPassword
			formError={formError}
			email={email}
			headerText="Verify your email"
			buttonText="Request password reset"
			queryString={queryParams}
			recaptchaSiteKey={recaptchaSiteKey}
			formPageTrackingName="forgot-password"
			showHelpCentreMessage
		>
			<MainBodyText>
				As a security measure, to verify your email, you will need to reset your
				password.
			</MainBodyText>
		</ResetPassword>
	);
};
