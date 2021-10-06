import React from 'react';
import { Meta } from '@storybook/react';

import { ResetPassword } from './ResetPassword';
import { renderMJML } from '../../testUtils';

export default {
  title: 'Email/Templates/ResetPassword',
  component: ResetPassword,
  parameters: { layout: 'fullscreen' },
} as Meta;

export const Default = () => {
  return renderMJML(
    <ResetPassword profileUrl="https://profile.theguardian.com" />,
  );
};
Default.storyName = 'with defaults';
