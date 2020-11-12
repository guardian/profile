/// <reference types="cypress" />

const qs = require('query-string');

class Onboarding {
  static URL = '/consents';

  static CONTENT = {
    SAVE_CONTINUE_BUTTON: 'Save and continue',
    GO_BACK_BUTTON: 'Go back',
  };

  static getBackButton() {
    return cy.contains(Onboarding.CONTENT.GO_BACK_BUTTON);
  }

  static getSaveAndContinueButton() {
    return cy.contains(Onboarding.CONTENT.SAVE_CONTINUE_BUTTON);
  }

  static getCheckboxes() {
    return cy.get('[type="checkbox"]');
  }

  static getOptinCheckboxes() {
    return this.getCheckboxes().not('[name*="_optout"]');
  }

  // static flow kick off function?
  goto({ failOnStatusCode = true, query = {}, path } = {}) {
    const querystring = qs.stringify(query);

    cy.visit(
      `${Onboarding.URL}${path ? path : ''}${
        querystring ? `?${querystring}` : ''
      }`,
      {
        failOnStatusCode,
      },
    );
  }
}

module.exports = Onboarding;
