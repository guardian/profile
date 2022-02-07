import '../../static/webpackPublicPath';
import { isAdBlockInUse } from '@guardian/commercial-core';
import type { CaptureContext } from '@sentry/types';
import type { BrowserOptions } from '@sentry/browser';

export const setupSentry = async (
  sentryConfiguration?: BrowserOptions,
): Promise<void> => {
  // Stub so that report functions exist before sentry has loaded.
  // eslint-disable-next-line functional/immutable-data
  window.guardian.modules = {
    sentry: {
      reportError: () => null,
      reportMessage: () => null,
    },
  };

  // Sentry lets you configure sampleRate to reduce the volume of events sent
  // but this filter only happens _after_ the library is loaded. The Guardian
  // measures page views in the billions so we only want to log 20% of errors that
  // happen but if we used sampleRate to do this we'd be needlessly downloading
  // Sentry 99% of the time. So instead we just do some basic math here
  // and use that to prevent the Sentry script from ever loading.
  // 80% of the time we don't want to remotely log errors with Sentry and so

  const randomCentile = Math.floor(Math.random() * 100) + 1; // A number between 1 - 100
  const sentryEnabled = !(randomCentile <= 80);

  // The other 20% of the time (randomCentile > 80) we continue
  try {
    // Downloading and initialising Sentry is asynchronous so we need a way
    // to ensure injection only happens once and to capture any other errors that
    // might happen while this script is loading
    let injected = false;

    interface SentryLogQueueEntry {
      error?: Error;
      message?: string;
      feature?: string;
      captureContext?: CaptureContext | undefined;
    }

    const sentryLogQueue: SentryLogQueueEntry[] = [];

    // Function that gets called when an error happens before Sentry is ready
    const injectSentry = async (sentryLogQueueEntry?: SentryLogQueueEntry) => {
      // Remember this Sentry log entry for later.
      if (sentryLogQueueEntry) sentryLogQueue.push(sentryLogQueueEntry);

      // Only inject once
      if (injected) {
        return;
      }
      injected = true;

      // Make this call blocking. We are queueing errors while we wait for this code to run
      // so we won't miss any and by waiting here we ensure we will never make calls we
      // expect to be blocked
      const adBlockInUse: boolean = await isAdBlockInUse();
      if (adBlockInUse) {
        // Ad Blockers prevent calls to Sentry from working so don't try to load the lib
        return;
      }

      // Load sentry.ts
      const SentryWrapper = await import(
        /* webpackChunkName: "sentry" */ './sentry'
      );

      // Initialise and retrieve our custom error and message methods.
      const { reportError, reportMessage } =
        SentryWrapper.init(sentryConfiguration);

      // Sentry takes over control of the window.onerror and
      // window.onunhandledrejection listeners but we need to
      // manually redefine our own custom error reporting function
      // eslint-disable-next-line functional/immutable-data
      window.guardian.modules.sentry.reportError = reportError;
      // Allow access to the full Sentry context for custom logging.
      // eslint-disable-next-line functional/immutable-data
      window.guardian.modules.sentry.reportMessage = reportMessage;

      // Now that we have the real reportError function available,
      // send any queued errors or messages.
      while (sentryLogQueue.length) {
        const queuedLogEntry = sentryLogQueue.shift();
        if (queuedLogEntry) {
          const { error, captureContext, message, feature } = queuedLogEntry;
          if (error) reportError(error, feature, captureContext);
          if (message) reportMessage(message, feature, captureContext);
        }
      }
    };

    if (sentryEnabled) {
      // This is how we lazy load Sentry. We setup custom functions and
      // listeners to inject Sentry when an error happens
      // eslint-disable-next-line functional/immutable-data
      window.onerror = (message, url, line, column, error) => {
        injectSentry({ error });
      };

      // eslint-disable-next-line functional/immutable-data
      window.onunhandledrejection = (event: undefined | { reason?: any }) =>
        event && injectSentry({ error: event.reason });
    }

    // We always register these handlers so that we can override `sentryEnabled` using
    // the `alwaysSample` flag. If both are false, we just error or log to the
    // console and bypass Sentry.

    // eslint-disable-next-line functional/immutable-data
    window.guardian.modules.sentry.reportError = (
      error,
      feature,
      captureContext,
      alwaysSample = false,
    ) => {
      if (sentryEnabled || alwaysSample) {
        injectSentry({ error, feature, captureContext }).catch((e) =>
          console.error(`injectSentry - error: ${e}`),
        );
      } else {
        console.error(error);
      }
    };

    // eslint-disable-next-line functional/immutable-data
    window.guardian.modules.sentry.reportMessage = (
      message,
      feature,
      captureContext,
      alwaysSample = false,
    ) => {
      if (sentryEnabled || alwaysSample) {
        injectSentry({ message, feature, captureContext }).catch((e) =>
          console.error(`injectSentry - error: ${e}`),
        );
      } else {
        console.info(message);
      }
    };
  } catch {
    // We failed to setup Sentry :(
  }
};
