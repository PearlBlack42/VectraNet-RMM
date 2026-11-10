import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

try {
  const descriptor =
    Object.getOwnPropertyDescriptor(window, 'fetch') ||
    Object.getOwnPropertyDescriptor(Window.prototype, 'fetch');
  if (descriptor && descriptor.get && !descriptor.set && descriptor.configurable) {
    let activeFetch = window.fetch.bind(window);
    Object.defineProperty(window, 'fetch', {
      configurable: true,
      enumerable: true,
      get: () => activeFetch,
      set: (fn) => {
        if (typeof fn === 'function') {
          activeFetch = fn;
        }
      },
    });
  }
} catch {
  // Descriptor already locked or configured
}

createRoot(document.getElementById('root')!).render(<App />);
