import React, { useState } from 'react';
import { FieldError } from '@/shared/model/ClientState';
import { TextInputProps } from '@guardian/source/react-components';
import { css } from '@emotion/react';
import ThemedTextInput from '@/client/components/ThemedTextInput';

interface PasscodeInputProps extends Omit<TextInputProps, 'label'> {
	passcode?: string;
	fieldErrors?: FieldError[];
}

const passcodeInputStyles = css`
	text-align: center;
`;

export const PasscodeInput = ({
	passcode = '',
	fieldErrors,
}: PasscodeInputProps) => {
	/**
	 * In gateway we normally avoid using client side javascript, but in this case
	 * we allow it as it an enhancement to the user experience and not required for
	 * the form to work.
	 */

	// This function removes all non-numeric characters from the input
	const sanitiseCode = (code: string) => {
		return code.replace(/\D*/g, '');
	};

	// Using an object to store the input value so that we re-render the component
	// whenever there is an user input, rather than only when the state changes
	const [input, setInput] = useState({ value: sanitiseCode(passcode) });

	// Update the input value on user input
	const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		setInput({
			value: sanitiseCode(e.target.value),
		});
	};

	// Update the input value on paste
	const onPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
		const paste = e.clipboardData.getData('text/plain');

		if (!paste) {
			return;
		}

		setInput({
			value: sanitiseCode(paste),
		});
	};

	return (
		<div>
			<ThemedTextInput
				label="Verification code"
				type="text"
				pattern="\d{6}"
				name="code"
				autoComplete="one-time-code"
				inputMode="numeric"
				maxLength={6}
				error={fieldErrors?.find((error) => error.field === 'code')?.message}
				defaultValue={passcode}
				cssOverrides={passcodeInputStyles}
				value={input.value}
				onChange={onChange}
				onPaste={onPaste}
			/>
		</div>
	);
};
