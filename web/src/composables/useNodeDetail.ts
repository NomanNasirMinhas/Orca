import { computed } from "vue";
import { store, actions } from "../store";
import type { NodeDetail } from "../api";

/**
 * Shared node-detail logic for the Info tab. Accepts getters for the SID and
 * detail source so the panel can bind to store.selectedNode / store.nodeDetail.
 */
export function useNodeDetail(
  getSid: () => string,
  getDetail: () => NodeDetail | null,
) {
  const node = computed(() => getDetail()?.node ?? null);
  const degree = computed(() => getDetail()?.degree ?? null);
  const sid = computed(() => getSid());

  const outDeg = computed(() => {
    const d = degree.value;
    if (!d) return [] as { pred: string; n: number }[];
    return Object.entries(d.out)
      .map(([pred, n]) => ({ pred, n }))
      .sort((a, b) => b.n - a.n);
  });

  const inDeg = computed(() => {
    const d = degree.value;
    if (!d) return [] as { pred: string; n: number }[];
    return Object.entries(d.in)
      .map(([pred, n]) => ({ pred, n }))
      .sort((a, b) => b.n - a.n);
  });

  const props = computed(() => {
    const p = node.value?.props;
    if (!p) return [] as { k: string; v: string }[];
    return Object.entries(p)
      .filter(([k]) => !["sid", "name", "kind", "highValue"].includes(k))
      .map(([k, v]) => ({ k, v }));
  });

  const kpathsReady = computed(
    () => store.kpathsGoal === sid.value && store.kpaths.length > 0,
  );

  // Whether this node is already in the live foothold, for toggling the
  // "Add to foothold" / "Remove from foothold" button label.
  const inFoothold = computed(() => !!sid.value && store.foothold.includes(sid.value));

  function copySid() {
    if (sid.value) navigator.clipboard?.writeText(sid.value);
  }

  function loadK(k = 5) {
    actions.loadKPaths(sid.value, k);
  }

  function showKPath(i: number) {
    const f = store.kpaths[i];
    if (f) actions.showPath(f);
  }

  // Toggle this node in/out of the live foothold; re-computes attack paths.
  function toggleFoothold() {
    if (!sid.value) return;
    if (inFoothold.value) actions.removeFoothold(sid.value);
    else actions.addFoothold(sid.value);
  }

  return {
    node, degree, sid, outDeg, inDeg, props, kpathsReady,
    inFoothold, copySid, loadK, showKPath, toggleFoothold,
  };
}
