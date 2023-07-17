describe('Reauthenticate flow, Okta enabled', () => {
	beforeEach(() => {
		// Disable redirect to /signin/success by default
		cy.setCookie(
			'GU_ran_experiments',
			new URLSearchParams({
				OptInPromptPostSignIn: Date.now().toString(),
			}).toString(),
		);
	});
	it('keeps User A signed in when User A attempts to reauthenticate', () => {
		cy
			.createTestUser({ isUserEmailValidated: true })
			?.then(({ emailAddress, finalPassword }) => {
				// First, sign in
				cy.visit(
					`/signin?returnUrl=${encodeURIComponent(
						`https://${Cypress.env('BASE_URI')}/consents/data`,
					)}`,
				);
				cy.get('input[name=email]').type(emailAddress);
				cy.get('input[name=password]').type(finalPassword);
				cy.get('[data-cy="main-form-submit-button"]').click();
				cy.url().should('include', '/consents/data');

				// Then, try to reauthenticate
				cy.visit(
					`/reauthenticate?returnUrl=${encodeURIComponent(
						`https://${Cypress.env('BASE_URI')}/consents/data`,
					)}`,
				);
				cy.get('input[name=email]').type(emailAddress);
				cy.get('input[name=password]').type(finalPassword);
				cy.get('[data-cy="main-form-submit-button"]').click();
				cy.url().should('include', '/consents/data');

				// Get the current session data
				cy.getCookie('sid').then((sidCookie) => {
					const sid = sidCookie?.value;
					expect(sid).to.exist;
					if (sid) {
						cy.getCurrentOktaSession(sid).then((session) => {
							expect(session.login).to.equal(emailAddress);
						});
					}
				});
			});
	});
	it('signs in User B when User B attempts to reauthenticate while User A is logged in', () => {
		// Create User A
		cy
			.createTestUser({ isUserEmailValidated: true })
			?.then(
				({ emailAddress: emailAddressA, finalPassword: finalPasswordA }) => {
					// First, sign in as User A
					cy.visit(
						`/signin?returnUrl=${encodeURIComponent(
							`https://${Cypress.env('BASE_URI')}/consents/data`,
						)}`,
					);
					cy.get('input[name=email]').type(emailAddressA);
					cy.get('input[name=password]').type(finalPasswordA);
					cy.get('[data-cy="main-form-submit-button"]').click();
					cy.url().should('include', '/consents/data');

					// Create User B
					cy
						.createTestUser({ isUserEmailValidated: true })
						?.then(
							({
								emailAddress: emailAddressB,
								finalPassword: finalPasswordB,
							}) => {
								// Then, try to reauthenticate as User B
								cy.visit(
									`/reauthenticate?returnUrl=${encodeURIComponent(
										`https://${Cypress.env('BASE_URI')}/consents/data`,
									)}`,
								);
								cy.get('input[name=email]').type(emailAddressB);
								cy.get('input[name=password]').type(finalPasswordB);
								cy.get('[data-cy="main-form-submit-button"]').click();
								cy.url().should('include', '/consents/data');

								// Get the current session data
								cy.getCookie('sid').then((sidCookie) => {
									const sid = sidCookie?.value;
									expect(sid).to.exist;
									if (sid) {
										cy.getCurrentOktaSession(sid).then((session) => {
											expect(session.login).to.equal(emailAddressB);
										});
									}
								});
							},
						);
				},
			);
	});
});
