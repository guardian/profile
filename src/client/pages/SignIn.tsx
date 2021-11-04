import React from 'react';
import { css } from '@emotion/react';
import { MainGrid } from '@/client/layouts/MainGrid';
import { Header } from '@/client/components/Header';
import { Footer } from '@/client/components/Footer';
import { PasswordInput } from '@/client/components/PasswordInput';
import { Nav } from '@/client/components/Nav';
import { Button } from '@guardian/src-button';
import { Routes } from '@/shared/model/Routes';
import { PageTitle } from '@/shared/model/PageTitle';
import { CsrfFormField } from '@/client/components/CsrfFormField';
import { Terms } from '@/client/components/Terms';
import { SocialButtons } from '@/client/components/SocialButtons';
import { Link } from '@guardian/src-link';
import { textSans } from '@guardian/src-foundations/typography';
import { gridItemSignInAndRegistration } from '@/client/styles/Grid';
import { border, space } from '@guardian/src-foundations';
import { from } from '@guardian/src-foundations/mq';
import { Divider } from '@guardian/source-react-components-development-kitchen';
import { SignInErrors } from '@/shared/model/Errors';
import { EmailInput } from '@/client/components/EmailInput';

export type SignInProps = {
  returnUrl?: string;
  email?: string;
  error?: string;
  oauthBaseUrl: string;
};

const passwordInput = css`
  margin-top: ${space[2]}px;

  ${from.mobileMedium} {
    margin-top: ${space[3]}px;
  }
`;

const resetPassword = css`
  ${textSans.small()}
`;

const signInButton = css`
  width: 100%;
  justify-content: center;
  margin-top: ${space[5]}px;
  ${from.mobileMedium} {
    margin-top: 16px;
  }
`;

const divider = css`
  /* Undoes the negative margin */
  margin-bottom: 0;
  margin-top: ${space[4]}px;
  ${from.mobileMedium} {
    margin-top: ${space[6]}px;
  }
  :before,
  :after {
    content: '';
    flex: 1 1;
    border-bottom: 1px solid ${border.secondary};
    margin: 8px;
  }
`;

const Links = ({ children }: { children: React.ReactNode }) => (
  <div
    css={css`
      margin-top: ${space[2]}px;
      ${from.tablet} {
        margin-top: 6px;
      }
    `}
  >
    {children}
  </div>
);

const getErrorContext = (error: string | undefined) => {
  if (error === SignInErrors.ACCOUNT_ALREADY_EXISTS) {
    return (
      <p>
        We cannot sign you in with your social account credentials. Please enter
        your account password below to sign in.
      </p>
    );
  }
};

const showSocialButtons = (
  error: string | undefined,
  returnUrl: string | undefined,
  oauthBaseUrl: string,
) => {
  if (error !== SignInErrors.ACCOUNT_ALREADY_EXISTS) {
    return (
      <>
        <Divider
          spaceAbove="loose"
          displayText="or continue with"
          cssOverrides={divider}
        />
        <SocialButtons returnUrl={returnUrl} oauthBaseUrl={oauthBaseUrl} />
      </>
    );
  }
};

export const SignIn = ({
  returnUrl,
  email,
  error,
  oauthBaseUrl,
}: SignInProps) => {
  const params = new URLSearchParams();
  if (returnUrl) params.append('returnUrl', returnUrl);
  const returnUrlQuery = params.toString();

  return (
    <>
      <Header />
      <Nav
        tabs={[
          {
            displayText: PageTitle.SIGN_IN,
            linkTo: Routes.SIGN_IN,
            isActive: true,
          },
          {
            displayText: PageTitle.REGISTRATION,
            linkTo: Routes.REGISTRATION,
            isActive: false,
          },
        ]}
      />
      <MainGrid
        gridSpanDefinition={gridItemSignInAndRegistration}
        errorOverride={error}
        errorContext={getErrorContext(error)}
      >
        <form method="post" action={`${Routes.SIGN_IN}?${returnUrlQuery}`}>
          <CsrfFormField />
          <EmailInput defaultValue={email} />
          <div css={passwordInput}>
            <PasswordInput label="Password" />
          </div>
          <Links>
            <Link
              subdued={true}
              href={Routes.RESET}
              cssOverrides={resetPassword}
            >
              Reset password
            </Link>
          </Links>
          <Terms />
          <Button css={signInButton} type="submit" data-cy="sign-in-button">
            Sign in
          </Button>
        </form>
        {showSocialButtons(error, returnUrl, oauthBaseUrl)}
      </MainGrid>
      <Footer />
    </>
  );
};
