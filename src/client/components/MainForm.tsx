import React, {
	createRef,
	PropsWithChildren,
	ReactNode,
	useCallback,
	useEffect,
	useState,
} from 'react';
import { css } from '@emotion/react';
import { Button, ButtonLink } from '@guardian/source/react-components';
import { CsrfFormField } from '@/client/components/CsrfFormField';
import {
	GuardianTerms,
	JobsTerms,
	RecaptchaTerms,
} from '@/client/components/Terms';
import { textSansBold15 } from '@guardian/source/foundations';
import {
	RecaptchaWrapper,
	UseRecaptchaReturnValue,
} from '@/client/lib/hooks/useRecaptcha';
import { CaptchaErrors } from '@/shared/model/Errors';
import { DetailedRecaptchaError } from '@/client/components/DetailedRecaptchaError';
import { RefTrackingFormFields } from '@/client/components/RefTrackingFormFields';
import { trackFormFocusBlur, trackFormSubmit } from '@/client/lib/ophan';
import { logger } from '@/client/lib/clientSideLogger';
import { ErrorSummary } from '@guardian/source-development-kitchen/react-components';
import {
	InformationBox,
	InformationBoxText,
} from '@/client/components/InformationBox';
import {
	mainSectionStyles,
	primaryButtonStyles,
	secondaryButtonStyles,
	errorMessageStyles,
} from '@/client/styles/Shared';
import locations from '@/shared/lib/locations';

export interface MainFormProps {
	wideLayout?: boolean;
	formAction: string;
	submitButtonText: string;
	submitButtonPriority?: 'primary' | 'tertiary';
	recaptchaSiteKey?: string;
	// These two props are used to pass a setter callback from the parent component
	// to MainForm, in instances when we want the error message to appear somewhere in the
	// parent component.
	setRecaptchaErrorMessage?: React.Dispatch<React.SetStateAction<string>>;
	setRecaptchaErrorContext?: React.Dispatch<
		React.SetStateAction<ReactNode | string>
	>;
	// These two props are used to display a form-level error message in this component.
	// This message appears alongside any message generated inside this component by the
	// formErrorMessage/formErrorContext setters.
	formErrorMessageFromParent?: string;
	formErrorContextFromParent?: ReactNode;
	hasGuardianTerms?: boolean;
	hasJobsTerms?: boolean;
	onSubmit?: (e: React.FormEvent<HTMLFormElement>) =>
		| {
				errorOccurred: boolean;
		  }
		| undefined;
	onInvalid?: React.FormEventHandler<HTMLFormElement> | undefined;
	formTrackingName?: string;
	disableOnSubmit?: boolean;
	largeFormMarginTop?: boolean;
	displayInline?: boolean;
	submitButtonLink?: boolean;
	hideRecaptchaMessage?: boolean;
	additionalTerms?: ReactNode;
}

const formStyles = (displayInline: boolean) => css`
	${mainSectionStyles};
	a {
		${textSansBold15};
	}
	${displayInline && 'display: inline-block;'}
`;

const buttonLinkStyles = css`
	${textSansBold15};
	color: var(--color-link);
	:hover {
		color: var(--color-link);
	}
`;

export const MainForm = ({
	children,
	wideLayout = false,
	formAction,
	submitButtonText,
	submitButtonPriority = 'primary',
	recaptchaSiteKey,
	setRecaptchaErrorMessage,
	setRecaptchaErrorContext,
	hasGuardianTerms = false,
	hasJobsTerms = false,
	onSubmit,
	onInvalid,
	formTrackingName,
	disableOnSubmit = false,
	formErrorMessageFromParent,
	formErrorContextFromParent,
	displayInline = false,
	submitButtonLink,
	hideRecaptchaMessage,
	additionalTerms,
}: PropsWithChildren<MainFormProps>) => {
	const recaptchaEnabled = !!recaptchaSiteKey;

	// These setters are used to set the error message locally, in this component.
	// We want to use these when we want to display errors at the level of the form.
	// We do this on the Registration and SignIn pages.
	const [formLevelErrorMessage, setFormLevelErrorMessage] = useState('');
	const [formLevelErrorContext, setFormLevelErrorContext] =
		useState<ReactNode>(null);

	// In a case where we have both a message generated by MainForm and one coming from the parent
	// via props, the locally generated one takes precedence.
	const errorMessage = formLevelErrorMessage || formErrorMessageFromParent;
	const errorContext = formLevelErrorContext || formErrorContextFromParent;

	const formRef = createRef<HTMLFormElement>();
	const [recaptchaState, setRecaptchaState] =
		useState<UseRecaptchaReturnValue>();

	const [isFormDisabled, setIsFormDisabled] = useState(false);

	const showFormLevelReportUrl = !!formLevelErrorContext;

	/**
	 * Executes the reCAPTCHA check and form submit tracking.
	 * Prevents the form from submitting until the reCAPTCHA check is complete.
	 * Disables the form on submit conditional on `disableOnSubmit`
	 * Keeps the form enabled if the outside submit handler reports an error
	 */
	const handleSubmit = useCallback(
		(event: React.FormEvent<HTMLFormElement>) => {
			if (formTrackingName) {
				trackFormSubmit(formTrackingName);
			}

			const errorInSubmitHandler = onSubmit?.(event)?.errorOccurred;

			if (disableOnSubmit) {
				if (errorInSubmitHandler === undefined) {
					if (!isFormDisabled) {
						setIsFormDisabled(true);
					}
				} else {
					const formSubmitSuccess = !errorInSubmitHandler;
					setIsFormDisabled(formSubmitSuccess);
				}
			}

			if (recaptchaEnabled && !recaptchaState?.token) {
				event.preventDefault();
				recaptchaState?.executeCaptcha();
			}
		},
		[
			formTrackingName,
			onSubmit,
			disableOnSubmit,
			recaptchaEnabled,
			recaptchaState,
			isFormDisabled,
		],
	);

	/**
	 * Submits the form once the reCAPTCHA check has been successfully completed.
	 */
	useEffect(() => {
		if (recaptchaEnabled) {
			const registerFormElement = formRef.current;
			if (recaptchaState?.token) {
				registerFormElement?.submit();
			}
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [recaptchaEnabled, recaptchaState, recaptchaState?.token]);

	useEffect(() => {
		if (recaptchaEnabled) {
			// Determine if something went wrong with the check.
			const recaptchaCheckFailed =
				recaptchaState?.error || recaptchaState?.expired;

			if (recaptchaCheckFailed && isFormDisabled) {
				// Re-enable the disabled form submit button
				setIsFormDisabled(false);
			}
		}
	}, [
		isFormDisabled,
		recaptchaEnabled,
		recaptchaState?.error,
		recaptchaState?.expired,
	]);

	useEffect(() => {
		if (recaptchaEnabled) {
			// Determine if something went wrong with the check.
			const recaptchaCheckFailed =
				recaptchaState?.error || recaptchaState?.expired;

			if (recaptchaCheckFailed) {
				logger.info('reCAPTCHA check failed');
			}

			// Used to show a more detailed reCAPTCHA error
			const showErrorContext = recaptchaCheckFailed;

			// Default to generic reCAPTCHA error message.
			// Show the retry message if the user has requested a check more than once.
			const recaptchaErrorMessage = CaptchaErrors.GENERIC;

			const recaptchaErrorContext = <DetailedRecaptchaError />;

			// Don't show the reCAPTCHA error if the key is set to 'test'
			const isTestKey = recaptchaSiteKey === 'test';
			const showRecaptchaError = recaptchaCheckFailed && !isTestKey;
			if (!showRecaptchaError) {
				return;
			}

			// If setters are provided, pass the error message and context to the parent component.
			// If they're not provided, display the error message and context as a form level error.
			if (recaptchaCheckFailed) {
				if (setRecaptchaErrorMessage) {
					setRecaptchaErrorMessage(recaptchaErrorMessage);
				} else {
					setFormLevelErrorMessage(recaptchaErrorMessage);
				}
			}
			if (showErrorContext) {
				if (setRecaptchaErrorContext) {
					setRecaptchaErrorContext(recaptchaErrorContext);
				} else {
					setFormLevelErrorContext(recaptchaErrorContext);
				}
			}
		}
	}, [
		recaptchaSiteKey,
		recaptchaEnabled,
		recaptchaState,
		recaptchaState?.error,
		recaptchaState?.expired,
		recaptchaState?.requestCount,
		setRecaptchaErrorContext,
		setRecaptchaErrorMessage,
	]);

	return (
		<form
			css={formStyles(displayInline)}
			method="post"
			action={formAction}
			onSubmit={handleSubmit}
			ref={formRef}
			onFocus={(e) =>
				formTrackingName && trackFormFocusBlur(formTrackingName, e, 'focus')
			}
			onBlur={(e) =>
				formTrackingName && trackFormFocusBlur(formTrackingName, e, 'blur')
			}
			onInvalid={(e) => onInvalid && onInvalid(e)}
			data-testid="main-form"
		>
			{errorMessage && (
				<ErrorSummary
					message={errorMessage}
					context={errorContext}
					errorReportUrl={
						showFormLevelReportUrl ? locations.REPORT_ISSUE : undefined
					}
					cssOverrides={errorMessageStyles}
				/>
			)}
			{recaptchaEnabled && (
				<RecaptchaWrapper
					recaptchaSiteKey={recaptchaSiteKey}
					setRecaptchaState={setRecaptchaState}
				/>
			)}
			<CsrfFormField />
			<RefTrackingFormFields />
			{children}
			{(additionalTerms ||
				hasGuardianTerms ||
				hasJobsTerms ||
				(recaptchaEnabled && !hideRecaptchaMessage)) && (
				<InformationBox>
					{hasGuardianTerms && <GuardianTerms />}
					{hasJobsTerms && <JobsTerms />}
					{additionalTerms && (
						<InformationBoxText>{additionalTerms}</InformationBoxText>
					)}
					{recaptchaEnabled && !hideRecaptchaMessage && <RecaptchaTerms />}
				</InformationBox>
			)}

			{submitButtonLink ? (
				<ButtonLink
					type="submit"
					data-cy="main-form-submit-button"
					disabled={isFormDisabled}
					aria-disabled={isFormDisabled}
					cssOverrides={buttonLinkStyles}
				>
					{submitButtonText}
				</ButtonLink>
			) : (
				<Button
					cssOverrides={
						submitButtonPriority === 'primary'
							? primaryButtonStyles(wideLayout ? 'half' : 'full')
							: secondaryButtonStyles(wideLayout ? 'half' : 'full')
					}
					type="submit"
					priority={submitButtonPriority}
					data-cy="main-form-submit-button"
					isLoading={isFormDisabled}
					disabled={isFormDisabled}
					aria-disabled={isFormDisabled}
					iconSide="right"
				>
					{submitButtonText}
				</Button>
			)}
		</form>
	);
};
