interface TitleBarProps {
  title?: string
  onNavigate?: (view: string) => void
  currentView?: string
}

export function TitleBar({ title = "MyAgent", onNavigate, currentView }: TitleBarProps) {
  return (
    <div className="h-12 bg-white border-b border-gray-200 flex items-center justify-between shadow-sm">
      <div className="flex items-center h-full">
        <div className="flex items-center gap-3 px-4">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-sm">MA</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-base font-bold text-gray-900">{title}</span>
            <span className="text-xs text-gray-500">IT Governed Agent</span>
          </div>
        </div>
      </div>

      {onNavigate && (
        <div className="flex items-center gap-2 flex-1 justify-center">
          <button
            onClick={() => onNavigate("chat")}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors cursor-pointer ${
              currentView === "chat"
                ? "bg-blue-100 text-blue-700"
                : "text-gray-600 hover:bg-gray-100"
            }`}
          >
            Chat
          </button>
        </div>
      )}

      <div className="flex items-center gap-3 h-full pr-4">
        <div className="flex items-center gap-2 px-3">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-gray-600 font-medium">Gateway Active</span>
        </div>
      </div>
    </div>
  )
}
