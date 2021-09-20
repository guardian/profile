import React, { FunctionComponent } from 'react';
import { css } from '@emotion/react';
import { headline } from '@guardian/src-foundations/typography';
import { from } from '@guardian/src-foundations/mq';
import { space } from '@guardian/src-foundations';

const header = css`
  width: 100%;
  margin-bottom: ${space[2]}px;
`;

const h2 = css`
  margin: 0;
  ${headline.small({ fontWeight: 'bold', lineHeight: 'tight' })}

  ${from.tablet} {
    ${headline.medium({ fontWeight: 'bold', lineHeight: 'tight' })}
  }
`;

export const PageHeader: FunctionComponent = ({ children }) => (
  <div css={header}>
    <h2 css={h2}>{children}</h2>
  </div>
);
