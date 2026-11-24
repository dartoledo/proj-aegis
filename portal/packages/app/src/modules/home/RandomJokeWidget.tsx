import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import { Button, FormControl, FormControlLabel, FormLabel, Radio, RadioGroup, Typography } from '@material-ui/core';

export type JokeType = 'any' | 'programming' | 'dad';

export type Joke = { setup: string; punchline: string };

export type RandomJokeContextValue = {
  loading: boolean;
  joke: Joke;
  type: JokeType;
  rerollJoke: () => Promise<void>;
  handleChangeType: (newType: JokeType) => void;
};

export const FALLBACK_JOKES: Record<'programming' | 'dad', readonly Joke[]> = {
  programming: [
    { setup: 'Why do programmers prefer dark mode?', punchline: 'Because light attracts bugs.' },
    { setup: 'How many programmers does it take to change a light bulb?', punchline: 'None, that\'s a hardware problem.' },
    { setup: 'Why did the programmer quit his job?', punchline: 'Because he didn\'t get arrays.' },
    { setup: 'What is a programmer\'s favorite hangout place?', punchline: 'Bit Café.' },
    { setup: 'Why do Java developers wear glasses?', punchline: 'Because they can\'t C#.' },
  ],
  dad: [
    { setup: 'What do you call a fake noodle?', punchline: 'An impasta.' },
    { setup: 'Why did the scarecrow win an award?', punchline: 'Because he was outstanding in his field.' },
    { setup: 'What do you call a bear with no teeth?', punchline: 'A gummy bear.' },
    { setup: 'Why don\'t eggs tell jokes?', punchline: 'They\'d crack you up.' },
  ],
};

export function pickFallbackJoke(type: JokeType, currentSetup?: string): Joke {
  let pool: readonly Joke[];
  if (type === 'programming') {
    pool = FALLBACK_JOKES.programming;
  } else if (type === 'dad') {
    pool = FALLBACK_JOKES.dad;
  } else {
    pool = [...FALLBACK_JOKES.programming, ...FALLBACK_JOKES.dad];
  }

  const filtered = pool.length > 1 ? pool.filter((item) => item.setup !== currentSetup) : pool;
  const effectivePool = filtered.length > 0 ? filtered : pool;
  return effectivePool[Math.floor(Math.random() * effectivePool.length)];
}

export async function fetchRandomJoke(type: JokeType, currentSetup?: string): Promise<Joke> {
  try {
    const url = `https://official-joke-api.appspot.com/jokes${type !== 'any' ? `/${type}` : ''}/random`;
    const response = await fetch(url);
    if (!response.ok) {
      return pickFallbackJoke(type, currentSetup);
    }
    const data = await response.json();
    const item: unknown = Array.isArray(data) ? data[0] : data;
    if (
      item &&
      typeof item === 'object' &&
      'setup' in item &&
      'punchline' in item &&
      typeof (item as Joke).setup === 'string' &&
      (item as Joke).setup.length > 0 &&
      typeof (item as Joke).punchline === 'string' &&
      (item as Joke).punchline.length > 0
    ) {
      return { setup: (item as Joke).setup, punchline: (item as Joke).punchline };
    }
    return pickFallbackJoke(type, currentSetup);
  } catch {
    return pickFallbackJoke(type, currentSetup);
  }
}

const RandomJokeContext = createContext<RandomJokeContextValue | undefined>(undefined);

export function ContextProvider({ children, defaultCategory }: { children: ReactNode; defaultCategory?: JokeType }) {
  const [loading, setLoading] = useState(true);
  const [joke, setJoke] = useState<Joke>({ setup: '', punchline: '' });
  const [type, setType] = useState<JokeType>(defaultCategory || 'programming');
  const currentSetupRef = useRef<string>('');
  const isMountedRef = useRef<boolean>(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const rerollJoke = useCallback(async () => {
    setLoading(true);
    try {
      const nextJoke = await fetchRandomJoke(type, currentSetupRef.current);
      if (isMountedRef.current) {
        currentSetupRef.current = nextJoke.setup;
        setJoke(nextJoke);
      }
    } catch {
      const fallback = pickFallbackJoke(type, currentSetupRef.current);
      if (isMountedRef.current) {
        currentSetupRef.current = fallback.setup;
        setJoke(fallback);
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [type]);

  const handleChangeType = useCallback((newType: JokeType) => {
    setType(newType);
  }, []);

  useEffect(() => {
    void rerollJoke();
  }, [rerollJoke]);

  return (
    <RandomJokeContext.Provider value={{ loading, joke, type, rerollJoke, handleChangeType }}>
      {children}
    </RandomJokeContext.Provider>
  );
}

export function useRandomJoke(): RandomJokeContextValue {
  const context = useContext(RandomJokeContext);
  if (context === undefined) {
    throw new Error('useRandomJoke must be used within a RandomJokeProvider');
  }
  return context;
}

export function Content() {
  const { joke, loading } = useRandomJoke();
  if (loading) {
    return <Typography paragraph>Loading...</Typography>;
  }
  return (
    <div>
      <Typography paragraph>{joke.setup}</Typography>
      <Typography paragraph>{joke.punchline}</Typography>
    </div>
  );
}

export function Actions() {
  const { rerollJoke } = useRandomJoke();
  return (
    <Button variant="contained" color="primary" onClick={() => { void rerollJoke(); }}>
      Reroll
    </Button>
  );
}

export function Settings() {
  const { type, handleChangeType } = useRandomJoke();
  return (
    <FormControl component="fieldset">
      <FormLabel component="legend">Joke Type</FormLabel>
      <RadioGroup
        aria-label="joke type"
        value={type}
        onChange={(e) => handleChangeType(e.target.value as JokeType)}
      >
        {(['any', 'programming', 'dad'] as const).map((t) => (
          <FormControlLabel
            key={t}
            value={t}
            control={<Radio />}
            label={t.charAt(0).toUpperCase() + t.slice(1)}
          />
        ))}
      </RadioGroup>
    </FormControl>
  );
}
