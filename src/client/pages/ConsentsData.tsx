import React from 'react';
import { css } from '@emotion/react';
import {
  neutral,
  space,
  remSpace,
  textSans,
} from '@guardian/source-foundations';
import {
  getAutoRow,
  gridItemColumnConsents,
  gridItemYourData,
  gridRow,
  subGridItemToggleSwitch,
  subGridOverrides,
} from '@/client/styles/Grid';
import { CONSENTS_PAGES } from '@/client/models/ConsentsPages';
import {
  heading,
  text,
  textBold,
  greyBorderTop,
} from '@/client/styles/Consents';
import { ConsentsLayout } from '@/client/layouts/ConsentsLayout';
import { ExternalLink } from '../components/ExternalLink';
import locations from '@/shared/lib/locations';
import { ToggleSwitchInput } from '../components/ToggleSwitchInput';

import { ConsentsForm } from '@/client/components/ConsentsForm';
import { ConsentsNavigation } from '@/client/components/ConsentsNavigation';

type ConsentsDataProps = {
  consented?: boolean;
  description?: string;
  name?: string;
  id: string;
};

const switchRow = css`
  border: 0;
  padding: 0;
  margin: ${space[4]}px 0 0 0;
  ${textSans.medium()}
`;

const removeMargin = css`
  margin: 0;
  -ms-grid-row: 1; /* fix top margin on IE11 */
`;

const toggleSwitchAlignment = css`
  justify-content: space-between;
  span {
    align-self: flex-start;
    margin-top: 4px;
  }
`;

const listBullets = css`
  list-style: none;
  padding-left: 0;
  text-indent: -18px; /* second line indentation */
  margin-left: 18px; /* second line indentation */
  li {
    font-size: 17px;
  }
  li:first-of-type {
    margin-top: 6px;
  }
  /* ::marker is not supported in IE11 */
  li::before {
    content: '';
    margin-right: ${space[2]}px;
    margin-top: ${space[2]}px;
    background-color: ${neutral[86]};
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }
`;

const labelStyles = css`
  ${textBold}
  label {
    line-height: ${remSpace[6]};
  }
`;

const marketingText = css`
  ${text}
  margin-top: ${space[4]}px;
`;

export const ConsentsData = ({ id, consented, name }: ConsentsDataProps) => {
  const autoRow = getAutoRow(1, gridItemColumnConsents);
  const autoYourDataRow = getAutoRow(1, gridItemYourData);
  const autoSwitchRow = getAutoRow(1, subGridItemToggleSwitch);

  const layoutProps = { title: 'Your data', current: CONSENTS_PAGES.YOUR_DATA };

  if (!name) {
    return (
      <ConsentsLayout {...layoutProps}>
        <ConsentsForm cssOverrides={autoRow()}>
          <ConsentsNavigation />
        </ConsentsForm>
      </ConsentsLayout>
    );
  }

  return (
    <ConsentsLayout {...layoutProps}>
      <h2 css={[heading, greyBorderTop, autoRow(), removeMargin]}>
        What we mean by your data
      </h2>
      <ul css={[text, listBullets, autoYourDataRow()]}>
        <li>Information you provide e.g. email address</li>
        <li>Products or services you buy from us</li>
        <li>
          Pages you view on theguardian.com or other Guardian websites when
          signed in
        </li>
      </ul>

      <ConsentsForm cssOverrides={autoRow()}>
        <div css={[gridRow, subGridOverrides]}>
          <fieldset css={[switchRow, greyBorderTop, autoSwitchRow()]}>
            <ToggleSwitchInput
              id={id}
              label={name}
              defaultChecked={consented ?? true} // legitimate interests so defaults to true
              cssOverrides={[labelStyles, toggleSwitchAlignment]}
            />
          </fieldset>
        </div>
        <div css={[autoRow()]}>
          <p css={[marketingText, greyBorderTop, autoRow()]}>
            You can change your settings under&nbsp;
            <ExternalLink href={locations.MMA_EMAIL_PREFERENCES} subdued={true}>
              Emails &amp; marketing
            </ExternalLink>
            &nbsp;on your Guardian account at any time.
          </p>
          <p css={[marketingText, autoRow()]}>
            Learn how we use data in our{' '}
            <ExternalLink href={locations.PRIVACY} subdued={true}>
              privacy policy
            </ExternalLink>
            .
          </p>
        </div>
        <ConsentsNavigation />
      </ConsentsForm>
    </ConsentsLayout>
  );
};
