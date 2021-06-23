import { Router, Request, Response } from 'express';
import { Example, ExamplePlainText } from '@/email/example/Example';
import { render } from 'mjml-react';
import { sendEmail } from '../lib/sendEmail';

const router = Router();

router.get('/inline-render-email', (_, res: Response) => {
  const email = Example;
  const { html } = render(email());

  return res.type('html').send(html);
});

// pre render the email at app start
const email = Example;
const { html } = render(email());

router.get('/pre-render-email', (_, res: Response) => {
  return res.type('html').send(html);
});

router.get('/send-example-email?:to', async (req: Request, res: Response) => {
  const { to, from } = req.query;

  if (typeof to !== 'string' || typeof from !== 'string') {
    return res.sendStatus(422);
  }

  try {
    await sendEmail(html, ExamplePlainText, 'Sign In | The Guardian', to, from);
  } catch (error) {
    if (error.statusCode) {
      return res.sendStatus(error.statusCode);
    }
    return res.sendStatus(500);
  }

  return res.sendStatus(200);
});

export default router;
