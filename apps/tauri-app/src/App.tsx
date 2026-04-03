function App() {
  const message = 'DefenseClaw Tauri App';

  return (
    <div className="w-full h-full bg-gray-900 text-gray-100 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4 text-cyan-400">{message}</h1>
        <p className="text-gray-400">Tauri v2 + React scaffold ready</p>
      </div>
    </div>
  );
}

export default App;
