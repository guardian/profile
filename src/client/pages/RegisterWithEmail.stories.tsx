import React from 'react';
import { Meta } from '@storybook/react';

import { RegisterWithEmail } from './RegisterWithEmail';
import { RegistrationProps } from './Registration';

export default {
	title: 'Pages/RegisterWithEmail',
	component: RegisterWithEmail,
	parameters: { layout: 'fullscreen' },
	args: {
		recaptchaSiteKey: '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
		oauthBaseUrl: 'https://oauth.theguardian.com/',
		queryParams: {
			returnUrl: 'https://www.theguardian.com/uk',
		},
	},
} as Meta<RegistrationProps>;

export const Default = (args: RegistrationProps) => (
	<RegisterWithEmail {...args} />
);
Default.story = {
	name: 'with defaults',
};

export const ReturnUrl = (args: RegistrationProps) => (
	<RegisterWithEmail
		{...args}
		queryParams={{ returnUrl: 'https://www.theguardian.com/uk' }}
	/>
);
ReturnUrl.story = {
	name: 'with returnUrl',
};

export const Email = (args: RegistrationProps) => (
	<RegisterWithEmail {...args} email="someone@theguardian.com" />
);
Email.story = {
	name: 'with email',
};

export const InvalidRecaptcha = (args: RegistrationProps) => (
	<RegisterWithEmail {...args} recaptchaSiteKey="invalid-key" />
);
InvalidRecaptcha.story = {
	name: 'with reCAPTCHA error',
};

export const WithJobs = (args: RegistrationProps) => (
	<RegisterWithEmail
		{...{ ...args, queryParams: { ...args.queryParams, clientId: 'jobs' } }}
	/>
);
WithJobs.story = {
	name: 'with Jobs terms',
};
