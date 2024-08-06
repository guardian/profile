import type { Meta } from '@storybook/react';
import React from 'react';
import { renderMJML } from '../../testUtils';
import { CompleteRegistration } from './CompleteRegistration';

export default {
	title: 'Email/Templates/CompleteRegistration',
	component: CompleteRegistration,
	parameters: {
		chromatic: {
			modes: {
				'dark desktop': { disable: true },
				'dark mobile': { disable: true },
			},
		},
	},
} as Meta;

export const Default = () => {
	return renderMJML(<CompleteRegistration />);
};
Default.storyName = 'with defaults';
