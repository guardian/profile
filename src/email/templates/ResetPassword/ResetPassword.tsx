import React from 'react';

import { Page } from '@/email/components/Page';
import { Button } from '@/email/components/Button';
import { Header } from '@/email/components/Header';
import { SubHeader } from '@/email/components/SubHeader';
import { Text } from '@/email/components/Text';
import { Footer } from '@/email/components/Footer';

export const ResetPassword = () => {
  return (
    <Page>
      <Header />
      <SubHeader>Reset password</SubHeader>
      <Text>
        <p>Hello,</p>
        <p>You’ve requested us to send you a link to reset your password.</p>
        <p>Please click the button below to reset your password.</p>
      </Text>
      <Button href={`https://profile.theguardian.com/c/TOKEN_PLACEHOLDER`}>
        Reset password
      </Button>
      <Footer />
    </Page>
  );
};
