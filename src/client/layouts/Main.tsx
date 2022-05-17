import React, { PropsWithChildren } from 'react';
import { css } from '@emotion/react';
import {
  from,
  headline,
  neutral,
  space,
  text,
} from '@guardian/source-foundations';
import {
  ErrorSummary,
  SuccessSummary,
} from '@guardian/source-react-components-development-kitchen';
import { gridRow, gridItem, SpanDefinition } from '@/client/styles/Grid';
import { Header, JobsHeader } from '@/client/components/Header';
import { Footer } from '@/client/components/Footer';
import useClientState from '@/client/lib/hooks/useClientState';

interface MainLayoutProps {
  pageHeader?: string;
  successOverride?: string;
  errorOverride?: string;
  errorContext?: React.ReactNode;
  useJobsHeader?: React.ReactNode;
}

const mainStyles = css`
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  margin: 0 auto;
  ${from.tablet} {
    border-left: 1px solid ${neutral[86]};
    border-right: 1px solid ${neutral[86]};
  }

  /* padding bottom */
  padding-bottom: 64px;
  ${from.tablet} {
    padding-bottom: 96px;
  }
  ${from.desktop} {
    padding-bottom: 120px;
  }
`;

const gridSpanDefinition: SpanDefinition = {
  TABLET: { start: 1, span: 8 },
  DESKTOP: { start: 2, span: 6 },
  LEFT_COL: { start: 3, span: 6 },
  WIDE: { start: 4, span: 6 },
};

const headerStyles = (hasSummary: boolean) => css`
  /* padding */
  padding-top: ${space[6]}px;
  padding-bottom: ${space[5]}px;

  ${hasSummary &&
  css`
    padding-top: 0;
  `}

  ${from.desktop} {
    ${hasSummary
      ? css`
          padding-top: 0;
        `
      : css`
          padding-top: ${space[9]}px;
        `}
  }

  /* margin */
  margin-bottom: ${space[1]}px;

  /* border */
  border-bottom: 1px solid ${neutral[86]};
`;

const pageTitleStyles = css`
  width: 100%;
  margin: 0;

  ${headline.small({ fontWeight: 'bold' })}
  font-size: 28px;
  ${from.desktop} {
    font-size: 32px;
  }

  color: ${text.primary};
`;

const summaryStyles = css`
  margin: ${space[6]}px 0;
`;

const bodyStyles = (hasTitleOrSummary: boolean) => css`
  ${!hasTitleOrSummary &&
  css`
    margin-top: ${space[1]}px;
  `}
`;

export const buttonStyles = ({ hasTerms = false, halfWidth = false }) => css`
  margin-top: 22px;
  justify-content: center;
  width: 100%;

  /* Set the cursor when disabled temporarily so we have a visual indication
   * until we have a loading spinner.
   * PR for loading spinner in Source: https://github.com/guardian/source/pull/1275
   */
  :disabled {
    cursor: not-allowed;
  }

  ${from.tablet} {
    ${halfWidth
      ? css`
          width: 50%;
        `
      : css`
          width: 100%;
        `}
  }

  ${hasTerms &&
  css`
    margin-top: 16px;
  `}
`;

export const MainLayout = ({
  children,
  pageHeader,
  successOverride,
  errorOverride,
  errorContext,
  useJobsHeader,
}: PropsWithChildren<MainLayoutProps>) => {
  const clientState = useClientState();
  const { globalMessage: { error, success } = {} } = clientState;

  const successMessage = successOverride || success;
  const errorMessage = errorOverride || error;

  const hasSummary = !!(errorMessage || successMessage);
  const hasTitleOrSummary = !!(pageHeader || hasSummary);

  return (
    <>
      {useJobsHeader ? <JobsHeader /> : <Header />}
      <main css={[mainStyles, gridRow]}>
        <section css={gridItem(gridSpanDefinition)}>
          {errorMessage && (
            <ErrorSummary
              cssOverrides={summaryStyles}
              message={errorMessage}
              context={errorContext}
            />
          )}
          {successMessage && !errorMessage && (
            <SuccessSummary
              cssOverrides={summaryStyles}
              message={successMessage}
            />
          )}
          {pageHeader && (
            <header css={headerStyles(hasSummary)}>
              <h1 css={[pageTitleStyles]}>{pageHeader}</h1>
            </header>
          )}
          <div css={bodyStyles(hasTitleOrSummary)}>{children}</div>
        </section>
      </main>
      <Footer />
    </>
  );
};
