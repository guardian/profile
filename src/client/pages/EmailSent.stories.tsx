/* eslint-disable functional/immutable-data */
import React from 'react';
import { Meta } from '@storybook/react';

import { EmailSent } from './EmailSent';

export default {
  title: 'Pages/EmailSent',
  component: EmailSent,
  parameters: { layout: 'fullscreen' },
} as Meta;

export const Defaults = () => <EmailSent previousPage="/reset" />;
Defaults.story = {
  name: 'with defaults',
};

export const WithEmail = () => (
  <EmailSent previousPage="/reset" email="example@theguardian.com" />
);
WithEmail.story = {
  name: 'with email',
};
