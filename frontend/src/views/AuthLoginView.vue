<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { onBeforeRouteUpdate, useRoute, useRouter } from 'vue-router';
import QRCode from 'qrcode';

import AuthLayout from '@/layouts/AuthLayout.vue';
import { ArrowPathIcon, QrCodeIcon } from '@heroicons/vue/24/outline';
import { startQrAuth, verifyQrAuth } from '@/api';
import { useI18n } from 'vue-i18n';
import { useAuthStore } from '@/stores/auth';
import { useFeaturesStore } from '@/stores/features';
import { useAppSettings } from '@/stores/appSettings';

const auth = useAuthStore();
const featuresStore = useFeaturesStore();
const appSettings = useAppSettings();
const { t } = useI18n();
const router = useRouter();
const route = useRoute();

const loginError = ref('');
const isStartingQr = ref(false);
const isPollingQr = ref(false);
const qrCode = ref('');
const qrRedirectLink = ref('');
const qrExpiresIn = ref(null);
const qrImageDataUrl = ref('');

const statusError = computed(() => auth.lastError || '');
const supportsQr = computed(() => Boolean(auth.strategies?.qr));
const isQrExpired = computed(() =>
  typeof qrExpiresIn.value === 'number' ? qrExpiresIn.value <= 0 : false
);
const qrImageUrl = computed(() => {
  if (isQrExpired.value) return '';
  return qrImageDataUrl.value;
});
const redirectTarget = computed(() => {
  const redirect = route.query?.redirect;
  if (typeof redirect === 'string' && redirect.trim()) {
    return redirect;
  }
  return '/browse/';
});

const helperTextClasses = 'text-sm text-red-400';
let pollTimer = null;
let expiryTimer = null;

const redirectToDestination = () => {
  const target = redirectTarget.value;
  router.replace(typeof target === 'string' ? target : '/browse/');
};

const redirectToDestinationWithReload = () => {
  const target = redirectTarget.value;
  const nextPath = typeof target === 'string' && target.trim() ? target : '/browse/';
  window.location.assign(nextPath);
};

const clearPolling = () => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
};

const clearExpiryCountdown = () => {
  if (expiryTimer) {
    clearInterval(expiryTimer);
    expiryTimer = null;
  }
};

const startExpiryCountdown = () => {
  clearExpiryCountdown();

  if (typeof qrExpiresIn.value !== 'number') return;

  expiryTimer = setInterval(() => {
    if (typeof qrExpiresIn.value !== 'number') return;

    if (qrExpiresIn.value <= 1) {
      qrExpiresIn.value = 0;
      clearExpiryCountdown();
      clearPolling();
      return;
    }

    qrExpiresIn.value -= 1;
  }, 1000);
};

const renderQrImage = async () => {
  if (!qrRedirectLink.value) {
    qrImageDataUrl.value = '';
    return;
  }

  try {
    qrImageDataUrl.value = await QRCode.toDataURL(qrRedirectLink.value, {
      scale: 8,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: {
        dark: '#111827',
        light: '#ffffff',
      },
    });
  } catch (_) {
    qrImageDataUrl.value = '';
    throw new Error('二维码生成失败。');
  }
};

const applyVerifyResult = async (result) => {
  if (typeof result?.expires_in === 'number') {
    qrExpiresIn.value = result.expires_in;
    if (qrExpiresIn.value <= 0) {
      clearPolling();
      clearExpiryCountdown();
    } else {
      startExpiryCountdown();
    }
  }

  if (result?.status !== 'authenticated') {
    return;
  }

  clearPolling();
  redirectToDestinationWithReload();
};

const pollQrStatus = async () => {
  if (!qrCode.value || isPollingQr.value) return;

  isPollingQr.value = true;
  try {
    const result = await verifyQrAuth(qrCode.value);
    await applyVerifyResult(result);
  } catch (error) {
    if (error?.statusCode === 410) {
      qrExpiresIn.value = 0;
      clearPolling();
      clearExpiryCountdown();
      return;
    }

    loginError.value = error instanceof Error ? error.message : 'QR 认证状态查询失败。';
    clearPolling();
  } finally {
    isPollingQr.value = false;
  }
};

const startPolling = () => {
  clearPolling();
  pollTimer = setInterval(() => {
    void pollQrStatus();
  }, 2000);
};

const startQrFlow = async () => {
  loginError.value = '';
  clearPolling();
  clearExpiryCountdown();
  qrCode.value = '';
  qrRedirectLink.value = '';
  qrExpiresIn.value = null;
  qrImageDataUrl.value = '';

  if (!supportsQr.value) {
    loginError.value = '当前系统未启用 QR 登录。';
    return;
  }

  isStartingQr.value = true;
  try {
    const result = await startQrAuth();
    qrCode.value = typeof result?.code === 'string' ? result.code : '';
    qrRedirectLink.value = typeof result?.redirect_link === 'string' ? result.redirect_link : '';
    qrExpiresIn.value = typeof result?.expires_in === 'number' ? result.expires_in : null;

    if (!qrCode.value || !qrRedirectLink.value) {
      throw new Error('QR 认证初始化返回无效。');
    }

    await renderQrImage();
    startExpiryCountdown();
    startPolling();
  } catch (error) {
    loginError.value = error instanceof Error ? error.message : 'QR 认证初始化失败。';
  } finally {
    isStartingQr.value = false;
  }
};

const ensureAuthReady = async () => {
  if (!auth.hasStatus || auth.isLoading) {
    await auth.ensureStatus();
  }
};

onMounted(async () => {
  await ensureAuthReady();

  if (auth.requiresSetup) {
    const redirect = redirectTarget.value;
    router.replace({
      name: 'auth-setup',
      ...(redirect ? { query: { redirect } } : {}),
    });
    return;
  }

  if (auth.isAuthenticated) {
    redirectToDestination();
    return;
  }

  await startQrFlow();

  try {
    await featuresStore.ensureLoaded();
  } catch (_) {
    // Non-fatal; version info is optional
  }
});

const resetErrors = () => {
  loginError.value = '';
  auth.clearError();
};

const syncErrorFromRoute = (nextRoute) => {
  const query = nextRoute?.query || {};
  const errorDescription = query.error_description;
  const error = query.error;
  const message =
    typeof errorDescription === 'string' && errorDescription.trim()
      ? errorDescription.trim()
      : typeof error === 'string' && error.trim()
        ? error.trim()
        : '';

  if (message && !loginError.value) {
    loginError.value = message;
  }

  if (typeof query.error === 'string' || typeof query.error_description === 'string') {
    const cleanedQuery = { ...query };
    delete cleanedQuery.error;
    delete cleanedQuery.error_description;
    router.replace({ query: cleanedQuery });
  }
};

syncErrorFromRoute(route);
onBeforeRouteUpdate((to) => {
  syncErrorFromRoute(to);
});

onUnmounted(() => {
  clearPolling();
  clearExpiryCountdown();
});
</script>

<template>
  <AuthLayout :version="featuresStore.version" :is-loading="auth.isLoading">
    <template #heading>
      <p class="text-3xl font-black leading-tight tracking-tight text-white">
        {{ $t('auth.login.welcome') }}
      </p>
    </template>

    <div class="space-y-4">
      <div class="rounded-2xl border border-white/10 bg-white/5 p-4">
        <p class="text-sm text-white/80">请使用手机扫码完成登录</p>
        <p v-if="qrExpiresIn != null" class="mt-1 text-xs text-white/50">
          二维码有效期：{{ qrExpiresIn }} 秒
        </p>
      </div>

      <div
        class="rounded-2xl border border-white/10 bg-black/20 p-4 flex items-center justify-center min-h-[292px]"
      >
        <img
          v-if="qrImageUrl && !isQrExpired"
          :src="qrImageUrl"
          alt="QR login"
          class="h-[260px] w-[260px] rounded-xl bg-white p-2"
        />
        <button
          v-else-if="isQrExpired"
          type="button"
          class="h-12 px-5 rounded-xl bg-neutral-100 hover:bg-neutral-100/90 active:bg-neutral-100/70 font-semibold text-neutral-900 inline-flex items-center justify-center gap-2"
          :disabled="isStartingQr"
          @click="startQrFlow"
        >
          <ArrowPathIcon class="h-5 w-5" />
          {{ isStartingQr ? '正在刷新二维码...' : '二维码已过期，点击刷新' }}
        </button>
        <div v-else class="text-white/60 text-sm inline-flex items-center gap-2">
          <QrCodeIcon class="h-5 w-5" />
          正在生成二维码...
        </div>
      </div>

      <a
        v-if="qrRedirectLink"
        :href="qrRedirectLink"
        target="_blank"
        rel="noreferrer"
        class="block text-center text-sm text-white/70 hover:text-white underline underline-offset-4"
      >
        无法扫码？在当前设备打开认证链接
      </a>
    </div>

    <p v-if="loginError || statusError" class="mt-4" :class="helperTextClasses">
      {{ loginError || statusError }}
    </p>
  </AuthLayout>
</template>
