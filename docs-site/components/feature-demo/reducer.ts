export interface PlayerState {
  stepIndex: number;
  isPlaying: boolean;
  completed: boolean;
  selectedVariant?: string;
  manualTabId?: string;
}

export type PlayerAction =
  | { type: 'AUTOPLAY_START' }
  | { type: 'PLAY'; lastStep: number }
  | { type: 'PAUSE' }
  | { type: 'NEXT'; lastStep: number }
  | { type: 'PREVIOUS' }
  | { type: 'RESTART'; play?: boolean }
  | { type: 'AUTOPLAY_NEXT'; stepIndex: number; lastStep: number }
  | { type: 'SELECT_TAB'; tabId: string }
  | { type: 'SELECT_VARIANT'; variantId: string; lastStep: number }
  | { type: 'SHOW_FINAL'; lastStep: number };

export function createInitialPlayerState(
  lastStep: number,
  selectedVariant?: string,
): PlayerState {
  return {
    stepIndex: lastStep,
    isPlaying: false,
    completed: true,
    selectedVariant,
  };
}

export function playerReducer(
  state: PlayerState,
  action: PlayerAction,
): PlayerState {
  switch (action.type) {
    case 'AUTOPLAY_START':
      return { ...state, stepIndex: 0, isPlaying: true, completed: false, manualTabId: undefined };
    case 'PLAY':
      return state.stepIndex >= action.lastStep
        ? { ...state, stepIndex: 0, isPlaying: true, completed: false, manualTabId: undefined }
        : { ...state, isPlaying: true, completed: false, manualTabId: undefined };
    case 'PAUSE':
      return { ...state, isPlaying: false };
    case 'NEXT': {
      const next = Math.min(state.stepIndex + 1, action.lastStep);
      return { ...state, stepIndex: next, isPlaying: false, completed: next === action.lastStep, manualTabId: undefined };
    }
    case 'PREVIOUS':
      return { ...state, stepIndex: Math.max(0, state.stepIndex - 1), isPlaying: false, completed: false, manualTabId: undefined };
    case 'RESTART':
      return { ...state, stepIndex: 0, isPlaying: Boolean(action.play), completed: false, manualTabId: undefined };
    case 'AUTOPLAY_NEXT':
      return {
        ...state,
        stepIndex: action.stepIndex,
        isPlaying: action.stepIndex < action.lastStep,
        completed: action.stepIndex === action.lastStep,
        manualTabId: undefined,
      };
    case 'SELECT_TAB':
      return { ...state, manualTabId: action.tabId, isPlaying: false };
    case 'SELECT_VARIANT':
      return { ...state, selectedVariant: action.variantId, stepIndex: action.lastStep, isPlaying: false, completed: true, manualTabId: undefined };
    case 'SHOW_FINAL':
      return { ...state, stepIndex: action.lastStep, isPlaying: false, completed: true, manualTabId: undefined };
  }
}
