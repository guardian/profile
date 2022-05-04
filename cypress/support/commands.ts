import '@testing-library/cypress/add-commands';

import { mockNext } from './commands/mockNext';
import { mockAll } from './commands/mockAll';
import { mockPurge } from './commands/mockPurge';
import { setMvtId } from './commands/setMvtId';
import {
  setAdFreeCookie,
  setDigitalSubscriberCookie,
} from './commands/setAdFreeCookie';
import { setEncryptedStateCookie } from './commands/setEncryptedStateCookie';
import { network } from './commands/network';
import { mockPattern } from './commands/mockPattern';
import { lastPayloadIs } from './commands/lastPayloadIs';
import { checkForEmailAndGetDetails } from './commands/getEmailDetails';
import { createTestUser } from './commands/testUser';
import {
  disableCMP,
  enableCMP,
  acceptCMP,
  declineCMP,
} from './commands/manageCmp';

Cypress.Commands.add('mockNext', mockNext);
Cypress.Commands.add('mockPattern', mockPattern); // unused, candidate for removal
Cypress.Commands.add('network', network);
Cypress.Commands.add('mockPurge', mockPurge);
Cypress.Commands.add('mockAll', mockAll);
Cypress.Commands.add('setMvtId', setMvtId);
Cypress.Commands.add('setAdFreeCookie', setAdFreeCookie);
Cypress.Commands.add('setDigitalSubscriberCookie', setDigitalSubscriberCookie);
Cypress.Commands.add('setEncryptedStateCookie', setEncryptedStateCookie);
Cypress.Commands.add('disableCMP', disableCMP);
Cypress.Commands.add('enableCMP', enableCMP);
Cypress.Commands.add('acceptCMP', acceptCMP);
Cypress.Commands.add('declineCMP', declineCMP);
Cypress.Commands.add('lastPayloadIs', lastPayloadIs);
Cypress.Commands.add('checkForEmailAndGetDetails', checkForEmailAndGetDetails);
Cypress.Commands.add('createTestUser', createTestUser);
