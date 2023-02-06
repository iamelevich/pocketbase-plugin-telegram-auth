import useTgWebAppAuth from './hooks/useTgWebAppAuth';

function App() {
  const [token, authRecord] = useTgWebAppAuth();

  if (!token) {
    return <div>Authentification...</div>
  }

  return (
    <main>
        <h1 className="text-3xl font-bold underline">
            Hello world! 111
        </h1>
        <pre>
            Token: {token}
        </pre>
        <pre>
            {JSON.stringify(authRecord, null, 2)}
        </pre>
    </main>
  )
}

export default App
