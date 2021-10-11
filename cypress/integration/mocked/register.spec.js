/// <reference types='cypress' />

import { injectAndCheckAxe } from '../../support/cypress-axe';
import {
  emailAddressInUse,
  invalidEmailAddress,
} from '../../support/idapi/guest';

describe('Registration flow', () => {
  beforeEach(() => {
    cy.mockPurge();
    cy.fixture('users').as('users');
  });

  context('A11y checks', () => {
    it('Has no detectable a11y violations on registration page', () => {
      cy.visit('/register');
      injectAndCheckAxe();
    });

    it('Has no detectable a11y violations on registration page with error', () => {
      cy.visit('/register');
      cy.get('input[name="email"]').type('Invalid email');
      cy.mockNext(500);
      cy.get('[data-cy=register-button]').click();
      injectAndCheckAxe();
    });
  });

  context('Registering', () => {
    it('shows a generic error message when registration fails', () => {
      cy.visit('/register?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fabout');
      cy.get('input[name="email"]').type('example@example.com');
      cy.mockNext(403, {
        status: 'error',
        errors: [
          {
            message: '',
          },
        ],
      });
      cy.get('[data-cy=register-button]').click();
      cy.contains('There was a problem registering, please try again.');
    });

    it('shows a generic error message when the email is in use', () => {
      cy.visit('/register?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fabout');
      cy.get('input[name="email"]').type('example@example.com');
      cy.mockNext(400, emailAddressInUse);
      cy.get('[data-cy=register-button]').click();
      cy.contains('There was a problem registering, please try again.');
    });

    it('shows a email field error message when no email is sent', () => {
      cy.visit('/register?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fabout');
      cy.get('input[name="email"]').type('placeholder@example.com');
      cy.mockNext(400, invalidEmailAddress);
      cy.get('[data-cy=register-button]').click();
      cy.contains('Email field must not be blank.');
    });

    it('redirects to email sent page upon successful guest registration', () => {
      cy.visit('/register?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fabout');
      cy.get('input[name="email"]').type('example@example.com');
      cy.mockNext(200, {
        status: 'success',
        errors: [],
      });
      cy.get('[data-cy=register-button]').click();
      cy.contains('Email sent');
      cy.contains('example@example.com');
    });
  });

  context('General IDAPI failure', () => {
    it('displays a generic error message', function () {
      cy.mockNext(500);
      cy.visit('/register?returnUrl=https%3A%2F%2Flocalhost%3A8861%2Fsignin');

      cy.get('input[name=email]').type('example@example.com');
      cy.get('[data-cy="register-button"]').click();

      cy.contains('There was a problem registering, please try again.');
    });
  });
});
