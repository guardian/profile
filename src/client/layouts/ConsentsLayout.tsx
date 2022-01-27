import React, { useContext, FunctionComponent } from 'react';
import { Footer } from '@/client/components/Footer';
import { ClientState } from '@/shared/model/ClientState';
import { ClientStateContext } from '@/client/components/ClientState';
import { css } from '@emotion/react';
import {
  Button,
  LinkButton,
  SvgArrowLeftStraight,
  SvgArrowRightStraight,
} from '@guardian/source-react-components';
import {
  getAutoRow,
  gridItem,
  gridItemColumnConsents,
} from '@/client/styles/Grid';
import { controls } from '@/client/layouts/shared/Consents';
import { ConsentsSubHeader } from '@/client/components/ConsentsSubHeader';
import { ConsentsBlueBackground } from '@/client/components/ConsentsBlueBackground';
import { ConsentsHeader } from '@/client/components/ConsentsHeader';

import { onboardingFormSubmitOphanTracking } from '@/client/lib/consentsTracking';
import { CsrfFormField } from '@/client/components/CsrfFormField';
import { buildUrlWithQueryParams } from '@/shared/lib/routeUtils';

interface ConsentsLayoutProps {
  children?: React.ReactNode;
  current?: string;
  title: string;
  bgColor?: string;
  showContinueButton?: boolean;
}

const form = css`
  display: flex;
  flex: 1 0 auto;
  flex-direction: column;
`;

// fixes overlapping text issue in IE
// derived from this solution https://stackoverflow.com/a/49368815
const ieFlexFix = css`
  flex: 0 0 auto;
`;

const mainStyles = css`
  display: flex;
  flex-direction: column;
  flex: 1 0 auto;
`;

const sectionStyles = css`
  display: flex;
  flex-direction: column;
  flex: 1 0 auto;
`;

const navigationControls = css`
  display: flex;
  justify-content: space-between;
`;

export const ConsentsLayout: FunctionComponent<ConsentsLayoutProps> = ({
  children,
  current,
  title,
  bgColor,
  showContinueButton = true,
}) => {
  const autoRow = getAutoRow(1, gridItemColumnConsents);
  const clientState: ClientState = useContext(ClientStateContext);
  const {
    pageData = {},
    globalMessage: { error, success } = {},
    queryParams,
  } = clientState;
  const { page = '', previousPage, geolocation } = pageData;

  const optionalBgColor =
    bgColor &&
    css`
      &:before {
        background-color: ${bgColor};
        opacity: 0.4;
      }
    `;
  return (
    <>
      <ConsentsHeader
        error={error}
        success={success}
        geolocation={geolocation}
      />
      <main css={mainStyles}>
        <ConsentsSubHeader autoRow={autoRow} title={title} current={current} />
        <form
          css={form}
          action={buildUrlWithQueryParams(
            '/consents/:page',
            { page },
            queryParams,
          )}
          method="post"
          onSubmit={({ target: form }) => {
            onboardingFormSubmitOphanTracking(
              page,
              pageData,
              // have to explicitly type as HTMLFormElement as typescript can't infer type of the event.target
              form as HTMLFormElement,
            );
          }}
        >
          <CsrfFormField />

          <section css={sectionStyles}>
            <div css={[ieFlexFix, optionalBgColor]}>{children}</div>
            <ConsentsBlueBackground>
              <div css={[gridItem(gridItemColumnConsents), controls]}>
                <div css={navigationControls}>
                  {previousPage && (
                    <LinkButton
                      iconSide="left"
                      icon={<SvgArrowLeftStraight />}
                      href={buildUrlWithQueryParams(
                        '/consents/:page',
                        {
                          page: previousPage,
                        },
                        queryParams,
                      )}
                      priority="tertiary"
                    >
                      Go back
                    </LinkButton>
                  )}
                  {!error && showContinueButton && (
                    <Button
                      iconSide="right"
                      nudgeIcon={true}
                      icon={<SvgArrowRightStraight />}
                      type="submit"
                    >
                      Continue
                    </Button>
                  )}
                </div>
              </div>
            </ConsentsBlueBackground>
          </section>
        </form>
      </main>
      <Footer />
    </>
  );
};
