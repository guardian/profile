export interface NewsLetter {
  id: string;
  nameId: string;
  description: string;
  frequency?: string;
  name: string;
  subscribed?: boolean;
}

export interface NewsletterPatch {
  id: string;
  subscribed: boolean;
}

export enum Newsletters {
  DOWN_TO_EARTH = '4147',
  FIRST_EDITION_UK = '4156',
  THE_LONG_READ = '4165',
  // US newsletters
  MORNING_BRIEFING_US = '4300',
  // AUS newsletters
  MORNING_MAIL_AU = '4148',
  AFTERNOON_UPDATE_AU = '6023',
  FIVE_GREAT_READS_AU = '6019',
  SAVED_FOR_LATER_AU = '6003',
}

export const ALL_NEWSLETTER_IDS = Object.values(Newsletters);
