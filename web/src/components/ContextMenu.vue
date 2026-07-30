<script setup lang="ts">
import { onMounted, onBeforeUnmount } from "vue";
import { store, actions } from "../store";

// BloodHound-style right-click context menu, teleported to body and positioned
// at the viewport coords Sigma reported for the right-click. Dispatches to the
// same store actions the Info tab exposes. Closes on backdrop click, right-click
// elsewhere, Escape, or any item pick.

function close() {
  store.menu = { ...store.menu, open: false };
}
function pick(fn: () => void) {
  fn();
  close();
}
function onKey(e: KeyboardEvent) {
  if (e.key === "Escape") close();
}
onMounted(() => window.addEventListener("keydown", onKey));
onBeforeUnmount(() => window.removeEventListener("keydown", onKey));

const sid = () => store.menu.sid;
</script>

<template>
  <Teleport to="body">
    <div
      v-if="store.menu.open"
      class="ctx-backdrop"
      @click="close"
      @contextmenu.prevent="close"
    >
      <ul
        class="ctx-menu"
        :style="{ left: store.menu.x + 'px', top: store.menu.y + 'px' }"
        @click.stop
      >
        <li @click="pick(() => actions.setStartNode(sid()))">
          <span class="ic">◉</span>Set as Start Node
        </li>
        <li @click="pick(() => actions.setEndNode(sid()))">
          <span class="ic">◎</span>Set as End Node
        </li>
        <li class="sep"></li>
        <li @click="pick(() => actions.findPathTo(sid()))">
          <span class="ic">→</span>Find Shortest Path to Here
        </li>
        <li @click="pick(() => actions.findPathFrom(sid()))">
          <span class="ic">←</span>Find Shortest Path from Here
        </li>
        <li @click="pick(() => actions.runStartEndPath())">
          <span class="ic">⇄</span>Run Start→End Path
        </li>
        <li class="sep"></li>
        <li @click="pick(() => actions.expandNeighbors(sid()))">
          <span class="ic">+</span>Expand
        </li>
        <li @click="pick(() => actions.removeNodeFromGraph(sid()))" class="danger">
          <span class="ic">✕</span>Remove Node
        </li>
      </ul>
    </div>
  </Teleport>
</template>

<style scoped>
.ctx-backdrop {
  position: fixed;
  inset: 0;
  z-index: 50;
}
.ctx-menu {
  position: fixed;
  z-index: 51;
  min-width: 230px;
  list-style: none;
  margin: 0;
  padding: 6px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
  font-size: 12px;
}
.ctx-menu li {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border-radius: 5px;
  cursor: pointer;
  color: var(--fg);
}
.ctx-menu li:hover { background: var(--panel-2); }
.ctx-menu li .ic { color: var(--muted); width: 14px; text-align: center; }
.ctx-menu li.danger { color: var(--hi); }
.ctx-menu li.danger:hover { background: rgba(232, 74, 73, 0.12); }
.ctx-menu li.sep { height: 1px; padding: 0; margin: 4px 0; background: var(--line); cursor: default; }
.ctx-menu li.sep:hover { background: var(--line); }
</style>