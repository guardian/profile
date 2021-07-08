/// <reference types='cypress' />

describe('Password reset flow', () => {
  context('Account exists', () => {
    // This test depends on this Mailslurp account already being registered
    const existing = {
      email: '0298a96c-1028-4e3d-b943-a2b478c84dbd@mailslurp.com',
      inbox: '0298a96c-1028-4e3d-b943-a2b478c84dbd',
    };

    it('shows a confirmation page when the reset password button is pressed', () => {
      cy.emptyInbox(existing.inbox).then(() => {
        cy.visit('/signin');
        cy.contains('Reset password').click();
        cy.contains('Forgotten password');
        cy.get('input[name=email]').type(existing.email);
        cy.get('[data-cy="reset-password-button"]').click();
        cy.contains('Please check your inbox', { timeout: 5000 });
        cy.waitForLatestEmail(existing.inbox, { timeout: 10000 }).then(
          (email) => {
            // extract the reset token (so we can reset this reader's password)
            const match = email.body.match(/reset-password\/([^"]*)/);
            const token = match[1];
            cy.visit(`/reset-password/${token}`);
            cy.get('input[name=password]').type('0298a96c-1028!@#');
            cy.get('input[name=password_confirm]').type('0298a96c-1028!@#');
            cy.get('[data-cy="change-password-button"]').click();
            cy.contains('Password Changed');
          },
        );
      });
    });
  });
});
