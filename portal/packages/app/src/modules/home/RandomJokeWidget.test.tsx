import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Actions, Content, ContextProvider, FALLBACK_JOKES, Settings, fetchRandomJoke, pickFallbackJoke, useRandomJoke } from './RandomJokeWidget';

describe('RandomJokeWidget', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('falls back to local joke when fetch rejects with TypeError: Failed to fetch', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    const joke = await fetchRandomJoke('programming');
    expect(FALLBACK_JOKES.programming).toContain(joke);
  });

  test('falls back to local joke when fetch returns HTTP 503', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 503 });
    const joke = await fetchRandomJoke('dad');
    expect(FALLBACK_JOKES.dad).toContain(joke);
  });

  test('returns remote joke when API responds with valid payload', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ setup: 'Remote setup?', punchline: 'Remote punchline!' }],
    });
    const result = await fetchRandomJoke('programming');
    expect(result).toEqual({ setup: 'Remote setup?', punchline: 'Remote punchline!' });
  });

  test('pickFallbackJoke avoids repeating currentSetup', () => {
    const currentSetup = FALLBACK_JOKES.programming[0].setup;
    const result = pickFallbackJoke('programming', currentSetup);
    expect(result.setup).not.toBe(currentSetup);
  });

  test('renders fallback joke and handles reroll and category change when fetch fails', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    render(
      <ContextProvider>
        <Content />
        <Actions />
        <Settings />
      </ContextProvider>
    );

    await waitFor(() => {
      expect(screen.queryByText('Loading...')).toBeNull();
    });

    const programmingSetups = FALLBACK_JOKES.programming.map((j) => j.setup);
    const foundProgramming = programmingSetups.some((s) => document.body.textContent?.includes(s));
    expect(foundProgramming).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Reroll' }));

    fireEvent.click(screen.getByRole('radio', { name: 'Dad' }));

    await waitFor(() => {
      const dadSetups = FALLBACK_JOKES.dad.map((j) => j.setup);
      const foundDad = dadSetups.some((s) => document.body.textContent?.includes(s));
      expect(foundDad).toBe(true);
    });
  });

  test('throws when useRandomJoke is used outside ContextProvider', () => {
    const originalConsoleError = console.error;
    console.error = jest.fn();

    function TestComponent() {
      useRandomJoke();
      return null;
    }

    expect(() => render(<TestComponent />)).toThrow(
      'useRandomJoke must be used within a RandomJokeProvider'
    );

    console.error = originalConsoleError;
  });
});
