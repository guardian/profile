import { Router } from 'express';

import { default as core } from './core';
import { default as reset } from './reset';
import { default as signIn } from './signIn';
import { default as changePassword } from './changePassword';
import { default as consents } from './consents';
import { default as verifyEmail } from './verifyEmail';
import { noCache } from '@/server/lib/middleware/cache';

const router = Router();

// core routes for the app, e.g. healthcheck, static routes
router.use(core);

// request reset password routes
router.use(noCache, reset);

// request sign in routes
router.use(noCache, signIn);

// change password routes
router.use(noCache, changePassword);

// consents routes
router.use(noCache, consents);

// verify email routes
router.use(noCache, verifyEmail);

export default router;
