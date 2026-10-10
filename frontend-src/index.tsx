import { createRoot, type Root } from 'react-dom/client';
import tokenStyles from '@xsec/design-tokens/styles.css';
import componentStyles from '@xsec/ui-react/styles.css';
import styles from './styles.css';
import { BinaryApp } from './app';
import { BinaryController } from './controller';
import { PluginTheme, readTheme } from './theme';
import type { Context, Host } from './core';

export function createController(host: Host) {
  const controller = new BinaryController(host);
  let root: Root | undefined;
  console.debug('binary.frontend.activated', { apiVersion: host.apiVersion });
  return {
    mount(element: HTMLElement, context: Context = host.context) {
      if (root) throw Error('二进制分析页面已经挂载');
      const initial = readTheme();
      root = createRoot(element);
      root.render(<><style>{tokenStyles + componentStyles + styles}</style><PluginTheme host={host} initial={initial} onFailure={controller.dispose}>
        <BinaryApp controller={controller}/></PluginTheme></>);
      return controller.mount().then(() => controller.update(context));
    },
    update(context: Context = host.context) { return controller.update(context); },
    dispose() { controller.dispose(); root?.unmount(); root = undefined; },
  };
}
