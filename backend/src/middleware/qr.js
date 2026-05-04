const logger = require('../utils/logger');
const { auth: envAuthConfig } = require('../config/index');
const { ValidationError, InternalError, AppError } = require('../errors/AppError');

const DEFAULT_TIMEOUT_MS = 5000;

const getQrConfig = () => (envAuthConfig && envAuthConfig.qr) || {};

const assertQrEnabled = () => {
  const qr = getQrConfig();

  if (!qr.enabled || !qr.qrAuthUrl) {
    throw new ValidationError('QR authentication is not configured.');
  }

  return qr;
};

const buildQrUrl = (pathname) => {
  const { qrAuthUrl } = assertQrEnabled();
  const baseUrl = qrAuthUrl.endsWith('/') ? qrAuthUrl : `${qrAuthUrl}/`;
  return new URL(pathname.replace(/^\//, ''), baseUrl).toString();
};

const fetchQrJson = async (pathname, { method = 'POST', body } = {}) => {
  const qr = assertQrEnabled();
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS) : null;
  const url = buildQrUrl(pathname);

  try {
    const response = await fetch(url, {
      method,
      headers: {
        Accept: 'application/json',
        ...(qr.qrAuthKey ? { 'X-API-Key': qr.qrAuthKey } : {}),
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller ? controller.signal : undefined,
    });

    const payload = await response.json().catch(() => null);

    if (!response.ok) {
      logger.warn(
        {
          url,
          status: response.status,
          payload,
        },
        'QR auth service request failed'
      );

      const message =
        (payload && (payload.error || payload.message)) ||
        `QR auth service request failed with status ${response.status}`;

      // Preserve upstream 4xx status (e.g. 410 expired code) so frontend can react correctly.
      if (response.status >= 400 && response.status < 500) {
        throw new AppError(message, response.status);
      }

      throw new InternalError(message);
    }

    return payload;
  } catch (error) {
    if (error && error.isOperational) {
      throw error;
    }

    logger.warn({ err: error, url }, 'QR auth service is unavailable');
    throw new InternalError('QR auth service is unavailable.');
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
};

const startQrAuth = async () => fetchQrJson('/start');

const verifyQrAuth = async (code) => {
  if (typeof code !== 'string' || !code.trim()) {
    throw new ValidationError('QR authentication code is required.');
  }

  return fetchQrJson('/verify', {
    body: { code: code.trim() },
  });
};

module.exports = {
  getQrConfig,
  startQrAuth,
  verifyQrAuth,
};
