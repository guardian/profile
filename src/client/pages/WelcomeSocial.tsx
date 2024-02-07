import React from 'react';
import { MainLayout } from '@/client/layouts/Main';
import { MainForm } from '@/client/components/MainForm';
import { buildUrlWithQueryParams } from '@/shared/lib/routeUtils';
import { usePageLoadOphanInteraction } from '@/client/lib/hooks/usePageLoadOphanInteraction';
import { RegistrationProps } from '@/client/pages/Registration';
import { css } from '@emotion/react';
import {
	palette,
	remHeight,
	remWidth,
	space,
	textSans,
} from '@guardian/source-foundations';
import { MainBodyText } from '@/client/components/MainBodyText';
import {
	SvgAppleBrand,
	SvgGoogleBrand,
	SvgTickRound,
} from '@guardian/source-react-components';
import { RegistrationMarketingConsentFormField } from '@/client/components/RegistrationMarketingConsentFormField';
import { SocialProvider } from '@/shared/model/Social';
import { RegistrationNewsletterFormField } from '@/client/components/RegistrationNewsletterFormField';
import { GeoLocation } from '@/shared/model/Geolocation';
import { SATURDAY_EDITION_SMALL_SQUARE_IMAGE } from '@/client/assets/newsletters';
import { RegistrationConsentsFormFields } from '@/shared/model/Consent';
import { RegistrationNewslettersFormFields } from '@/shared/model/Newsletter';
import { registrationFormSubmitOphanTracking } from '@/client/lib/consentsTracking';

const inlineMessage = (socialProvider: SocialProvider) => css`
	display: flex;
	align-items: flex-start;
	${textSans.large()};

	span {
		${socialProvider === 'google' &&
		css`
			margin-left: -4px;
		`}
		${socialProvider === 'apple' &&
		css`
			margin-left: -6px;
		`}
	}

	svg {
		fill: currentColor;
		flex: none;
		width: ${remWidth.iconMedium}rem;
		height: ${remHeight.iconMedium}rem;
		/* a visual kick to vertically/horizontally align the social icons with the column and row of text */
		${socialProvider === 'google' &&
		css`
			transform: translate(-4px, -2px);
		`}
		${socialProvider === 'apple' &&
		css`
			transform: translate(-6px, -2px);
		`}

		&:last-of-type {
			/* a visual kick to vertically align the check icon with and row of text */
			transform: translate(0px, -2px);
			color: ${palette.success[400]};
			margin-left: ${space[1]}px;
		}
	}
`;

export type WelcomeSocialProps = RegistrationProps & {
	socialProvider: SocialProvider;
	geolocation?: GeoLocation;
};

export const WelcomeSocial = ({
	queryParams,
	formError,
	socialProvider,
	geolocation,
}: WelcomeSocialProps) => {
	const formTrackingName = 'register';

	usePageLoadOphanInteraction(formTrackingName);

	// don't show the Saturday Edition newsletter option for US and AU
	const showSaturdayEdition = !(['US', 'AU'] as GeoLocation[]).some(
		(location: GeoLocation) => location === geolocation,
	);

	return (
		<MainLayout>
			<MainForm
				formAction={buildUrlWithQueryParams('/welcome/social', {}, queryParams)}
				submitButtonText="Confirm"
				formTrackingName={formTrackingName}
				disableOnSubmit
				formErrorMessageFromParent={formError}
				largeFormMarginTop
				onSubmit={(e) => {
					registrationFormSubmitOphanTracking(e.target as HTMLFormElement);
					return undefined;
				}}
			>
				{socialProvider === 'google' && (
					<MainBodyText cssOverrides={inlineMessage(socialProvider)}>
						<SvgGoogleBrand />
						<span>Google account verified</span>
						<SvgTickRound />
					</MainBodyText>
				)}
				{socialProvider === 'apple' && (
					<MainBodyText cssOverrides={inlineMessage(socialProvider)}>
						<SvgAppleBrand />
						<span>Apple account verified</span>
						<SvgTickRound />
					</MainBodyText>
				)}
				<>
					{showSaturdayEdition && (
						<RegistrationNewsletterFormField
							id={RegistrationNewslettersFormFields.saturdayEdition.id}
							label={RegistrationNewslettersFormFields.saturdayEdition.label}
							context={
								RegistrationNewslettersFormFields.saturdayEdition.context
							}
							imagePath={SATURDAY_EDITION_SMALL_SQUARE_IMAGE}
						/>
					)}
					<RegistrationMarketingConsentFormField
						id={RegistrationConsentsFormFields.similarGuardianProducts.id}
						label={RegistrationConsentsFormFields.similarGuardianProducts.label}
					/>
				</>
			</MainForm>
		</MainLayout>
	);
};
