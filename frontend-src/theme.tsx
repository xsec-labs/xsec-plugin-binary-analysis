import { useLayoutEffect, useState, type ReactNode } from 'react';
import { ControlThemeProvider, ErrorState } from '@xsec/ui-react';
import { themeAttributes, type ThemeSettings } from '@xsec/design-tokens';
import { failure, type Host, type UiError } from './core';
function parseTheme(theme: Record<string, string>): ThemeSettings {
  const mode = theme['color-mode'], density = theme['ui-density'], motion = theme['reduce-motion'], size = theme['ui-font-size'];
  if (mode !== 'light' && mode !== 'dark') throw Error('Host 颜色模式无效');
  if (density !== 'compact' && density !== 'comfortable') throw Error('Host UI 密度无效');
  if (motion !== 'true' && motion !== 'false') throw Error('Host 减少动效设置无效');
  if (typeof size !== 'string' || !/^\d+(?:\.\d+)?px$/.test(size)) throw Error('Host UI 字号无效');
  const settings: ThemeSettings = { colorMode: mode, density, reducedMotion: motion === 'true', fontScale: Number(size.slice(0, -2)) / 14, locale: 'zh-CN' };
  themeAttributes(settings);
  return settings;
}
export function readTheme() {
  const style = getComputedStyle(document.documentElement);
  return parseTheme(Object.fromEntries(['color-mode', 'ui-density', 'reduce-motion', 'ui-font-size'].map(key => [key, style.getPropertyValue('--xsec-' + key).trim()])));
}
export function PluginTheme({ host, initial, onFailure, children }: {
  host: Host; initial: ThemeSettings; onFailure: () => void; children: ReactNode;
}) {
  const [settings, setSettings] = useState(initial), [error, setError] = useState<UiError>();
  useLayoutEffect(() => {
    let failed = false;
    const subscription = host.onTheme(theme => {
      if (failed) return;
      try { setSettings(parseTheme(theme)); }
      catch (cause) {
        failed = true; onFailure();
        const operationId = crypto.randomUUID();
        console.error('binary.theme.failed', { operation_id: operationId });
        setError(failure(cause, operationId));
      }
    });
    return () => subscription.dispose();
  }, [host, onFailure]);
  return <ControlThemeProvider settings={settings} className="ba-theme">{error ?
    <div className="ba-theme-error"><ErrorState title="显示设置无效" description={error.message} errorId={error.operationId}/>
      <p className="ba-note">请修正应用外观设置后重新载入插件。</p></div> : children}</ControlThemeProvider>;
}
