// goals.js — opencode plugin entry for the goals plugin.
// Exactly ONE plugin factory is exported (GoalPlugin). All pure logic and module-level
// state live behind goals-core.js (goals-k2j.1); this file only wires the factory + hooks.
// Pure logic is unit-tested by importing directly from goals-core.js (goals-k2j.6), so this
// entry imports only the symbols the hooks actually use.
import { createGoalDiagnostics } from "./diagnostics.js";
import {
  GOAL_EVALUATOR_AGENT,
  GOAL_RESEARCHER_AGENT,
  GOAL_RESEARCHER_STEPS,
  PERMISSION_ASKED_EVENTS,
  PERMISSION_REPLIED_EVENTS,
  QUESTION_ASKED_EVENTS,
  QUESTION_REJECTED_EVENTS,
  QUESTION_REPLIED_EVENTS,
  buildCompactionContext,
  bumpGoalGeneration,
  clearGoalToastFocus,
  evaluateGoal,
  focusGoalToast,
  getSessionID,
  handleGoalCommand,
  humanMessageText,
  isIdleEvent,
  loadPersistedState,
  modelFromInput,
  pauseGoal,
  permissionReplyRejected,
  persistState,
  persistencePaths,
  readOnlyPermission,
  recordHistory,
  registerGoalCommand,
  resumeActiveClock,
  showGoalToast,
  states,
  suspendActiveClock,
} from "./goals-core.js";

export const GoalPlugin = async (ctx) => {
  const diagnostics = createGoalDiagnostics(ctx);
  const pluginCtx = { ...ctx, diagnostics };
  const persistence = persistencePaths(pluginCtx);
  let configuredDefaultAgent = "build";
  await loadPersistedState(persistence, pluginCtx.client);

  return {
    config: async (cfg) => {
      await registerGoalCommand(cfg, import.meta.dirname);
      configuredDefaultAgent = cfg.default_agent || configuredDefaultAgent;
      cfg.agent = cfg.agent ?? {};
      cfg.agent[GOAL_EVALUATOR_AGENT] = {
        description:
          "Hidden /goal evaluator that gives the final structured verdict using transcript, diff, and read-only research evidence.",
        mode: "primary",
        hidden: true,
        model: cfg.model,
        temperature: 0,
        maxSteps: 1,
        permission: {
          "*": "deny",
          read: "deny",
          glob: "deny",
          grep: "deny",
          list: "deny",
          lsp: "deny",
          edit: "deny",
          bash: "deny",
          task: "deny",
          webfetch: "deny",
          websearch: "deny",
          skill: "deny",
          question: "deny",
          todowrite: "deny",
          external_directory: "deny",
        },
      };
      cfg.agent[GOAL_RESEARCHER_AGENT] = {
        description:
          "Hidden read-only /goal researcher that gathers file, search, docs, plan, and diff evidence before the final evaluator verdict.",
        mode: "primary",
        hidden: true,
        model: cfg.model,
        temperature: 0,
        maxSteps: GOAL_RESEARCHER_STEPS,
        permission: readOnlyPermission(),
      };
    },

    "chat.message": async (input, output) => {
      const state = states.get(input.sessionID);
      const resolvedAgent = output?.message?.agent ?? input.agent;
      if (!state || resolvedAgent === GOAL_EVALUATOR_AGENT || resolvedAgent === GOAL_RESEARCHER_AGENT) return;
      // goals-6oi: lastAgent/lastModel are the agent/model the build is *actually running under*;
      // sendContinuation (continuationAgent = state.lastAgent || ...) and stateModel feed them back
      // into future continuations and hidden prompts. The chat.message hook fires for EVERY user
      // message, including ones that are not genuine build turns: a /goal command/status turn (whose
      // parts command.execute.before has already replaced with goal-plugin parts) and any
      // plugin/host-synthetic message. Recording the agent/model from those drifts the continuation
      // identity onto whatever transient agent/model that command/status turn happened to use. Gate
      // the update on the presence of real human-authored content: on the installed @opencode-ai/
      // sdk@1.17.7 v1 shape, command/status turns carry only goal-plugin parts (metadata.source ===
      // "goal-plugin") and synthetic injections carry part.synthetic === true, so humanMessageText
      // (drops both) is empty for them and non-empty only for a genuine human build turn.
      const parts = output?.parts ?? output?.message?.parts ?? input.parts;
      if (!humanMessageText({ parts })) {
        return;
      }
      // new-1: a genuine human build turn while a goal is active is a takeover signal. Bump the
      // generation so any in-flight evaluateGoal/sendContinuation fails its next stillCurrent() check
      // (no auto-continue over the human), and set humanInterrupted so the next idle pauses even when
      // the human message is not the latest turn (e.g. a racing auto-continue already landed after it).
      if (state.status === "active") {
        state.humanInterrupted = true;
        bumpGoalGeneration(state);
        clearGoalToastFocus(input.sessionID, persistence);
      }
      if (resolvedAgent) {
        if (!state.initialAgent) state.initialAgent = resolvedAgent;
        state.lastAgent = resolvedAgent;
      }
      const model = modelFromInput(output?.message?.model) ?? modelFromInput(input.model);
      if (model) {
        if (!state.initialModel) state.initialModel = model;
        state.lastModel = model;
      }
      await persistState(persistence, pluginCtx.client);
    },

    "command.execute.before": async (input, output) => {
      if (input.command !== "goal") return;
      await handleGoalCommand(pluginCtx, persistence, input, output, configuredDefaultAgent);
    },

    event: async ({ event }) => {
      // new-14: the event hook is fire-and-forget (opencode never awaits it), so any throw would become
      // an unhandled rejection. A top-level guard structurally enforces the "never throw" invariant
      // rather than relying on every nested helper staying exception-free.
      try {
      const type = event?.type;
      const sessionID = getSessionID(event);
      const state = typeof sessionID === "string" ? states.get(sessionID) : undefined;

      if (PERMISSION_ASKED_EVENTS.has(type) || QUESTION_ASKED_EVENTS.has(type)) {
        // new-3: idempotent — only record the transition when it actually changes state, so a duplicate
        // event delivery (or the double-instantiated factory) does not double-append history/ledger.
        if (state && state.status === "active" && !state.blocked) {
          state.blocked = true;
          suspendActiveClock(state); // runaway-1: don't charge the wall-clock budget while blocked on a human
          bumpGoalGeneration(state);
          state.lastReason = "Waiting for a permission or question response.";
          await recordHistory(persistence, state, "blocked", state.lastReason);
          clearGoalToastFocus(sessionID, persistence);
          await showGoalToast(pluginCtx.client, state, { headline: "Goal waiting", variant: "warning" });
          await persistState(persistence, pluginCtx.client);
        }
        return;
      }

      if (PERMISSION_REPLIED_EVENTS.has(type) || QUESTION_REPLIED_EVENTS.has(type)) {
        if (state && state.status === "active") {
          if (PERMISSION_REPLIED_EVENTS.has(type) && permissionReplyRejected(event)) {
            await pauseGoal(pluginCtx, persistence, state, "Paused after a permission request was rejected.", "warning");
            return;
          }
          // new-3: idempotent — only unblock (and record it) when currently blocked.
          if (state.blocked) {
            state.blocked = false;
            resumeActiveClock(state); // runaway-1: credit the blocked interval back to the wall-clock budget
            bumpGoalGeneration(state);
            state.lastReason = "Permission or question response received; goal can continue.";
            await recordHistory(persistence, state, "unblocked", state.lastReason);
            await persistState(persistence, pluginCtx.client);
            await showGoalToast(pluginCtx.client, state, { headline: "Goal unblocked" });
            focusGoalToast(pluginCtx, persistence, sessionID);
          }
        }
        return;
      }

      if (QUESTION_REJECTED_EVENTS.has(type)) {
        if (state && state.status === "active") await pauseGoal(pluginCtx, persistence, state, "Paused after a question was rejected.", "warning");
        return;
      }

      if (type === "session.error") {
        if (state && state.status === "active") {
          if (state.evaluating) {
            state.lastReason = "Hidden /goal evaluation observed a session error; evaluation error handling will decide whether to retry or pause.";
            await recordHistory(persistence, state, "error", state.lastReason);
            await persistence.diagnostics?.emit({
              level: "error",
              event: "session_error_observed",
              message: state.lastReason,
              sessionID,
              hook: "event",
              outcome: "failure",
            });
            await persistState(persistence, pluginCtx.client);
            return;
          }
          await persistence.diagnostics?.emit({
            level: "error",
            event: "session_error_observed",
            message: "Paused active /goal after a session error",
            sessionID,
            hook: "event",
            outcome: "failure",
          });
          await pauseGoal(pluginCtx, persistence, state, "Paused after a session error.", "error");
        }
        return;
      }

      if (isIdleEvent(event) && state) {
        await evaluateGoal(pluginCtx, persistence, sessionID, state, configuredDefaultAgent);
      }
      } catch (error) {
        await pluginCtx.diagnostics?.emit({
          level: "error",
          event: "event_hook_error",
          message: "Swallowed an unexpected error in the goals event hook (fire-and-forget invariant).",
          hook: "event",
          outcome: "failure",
          error,
        });
      }
    },

    "experimental.session.compacting": async (input, output) => {
      if (!input?.sessionID || !output) return;
      const state = states.get(input.sessionID);
      if (!state) return;
      const context = buildCompactionContext(state);
      // new-28: the factory is double-instantiated and both instances share the states Map, so both
      // would push the same deterministic context block onto the same output.context — doubling the
      // injected goal block exactly when the context window is overflowing. Dedup by value.
      if (Array.isArray(output.context)) {
        if (!output.context.includes(context)) output.context.push(context);
      } else {
        output.context = [context];
      }
    },
  };
};
