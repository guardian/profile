import OnboardingPage from './onboarding_page';

class NewslettersPage extends OnboardingPage {
  static CONTENT = {
    ...OnboardingPage.CONTENT,
    NEWSLETTERS: {
      TODAY_UK: 'Guardian Today: UK',
      TODAY_US: 'Guardian Today: US',
      TODAY_AUS: 'Guardian Today: AUS',
      LONG_READ: 'The Long Read',
      GREEN_LIGHT: 'Green Light',
      BOOKMARKS: 'Bookmarks',
    },
  };
  static newsletterCheckboxWithTitle(title: string) {
    return cy
      .contains(title)
      .parent()
      .contains('Yes, sign me up')
      .find('input');
  }
  static URL = '/consents/newsletters';
}

export default NewslettersPage;
